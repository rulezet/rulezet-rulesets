rule TTP_XOR_QUAD_CurrentVersionRun_0055 {
  strings:
    $key_0055 = { 53 3a [2] 77 34 [2] 5c 18 [2] 72 3a [2] 66 21 [2] 69 3b [2] 77 26 [2] 75 27 [2] 6e 21 [2] 72 26 [2] 6e 09 }

  condition:
    any of them
}