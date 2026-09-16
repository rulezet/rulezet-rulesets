rule TTP_XOR_QUAD_CurrentVersionRun_0028 {
  strings:
    $key_0028 = { 53 47 [2] 77 49 [2] 5c 65 [2] 72 47 [2] 66 5c [2] 69 46 [2] 77 5b [2] 75 5a [2] 6e 5c [2] 72 5b [2] 6e 74 }

  condition:
    any of them
}