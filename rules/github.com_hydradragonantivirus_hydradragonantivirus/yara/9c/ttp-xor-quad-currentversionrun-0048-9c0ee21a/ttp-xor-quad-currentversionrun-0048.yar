rule TTP_XOR_QUAD_CurrentVersionRun_0048 {
  strings:
    $key_0048 = { 53 27 [2] 77 29 [2] 5c 05 [2] 72 27 [2] 66 3c [2] 69 26 [2] 77 3b [2] 75 3a [2] 6e 3c [2] 72 3b [2] 6e 14 }

  condition:
    any of them
}