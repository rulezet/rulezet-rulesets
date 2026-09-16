rule TTP_XOR_QUAD_CurrentVersionRun_0029 {
  strings:
    $key_0029 = { 53 46 [2] 77 48 [2] 5c 64 [2] 72 46 [2] 66 5d [2] 69 47 [2] 77 5a [2] 75 5b [2] 6e 5d [2] 72 5a [2] 6e 75 }

  condition:
    any of them
}