rule TTP_XOR_QUAD_CurrentVersionRun_0035 {
  strings:
    $key_0035 = { 53 5a [2] 77 54 [2] 5c 78 [2] 72 5a [2] 66 41 [2] 69 5b [2] 77 46 [2] 75 47 [2] 6e 41 [2] 72 46 [2] 6e 69 }

  condition:
    any of them
}