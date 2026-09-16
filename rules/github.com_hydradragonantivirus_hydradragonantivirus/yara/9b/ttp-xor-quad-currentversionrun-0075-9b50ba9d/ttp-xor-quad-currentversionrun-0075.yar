rule TTP_XOR_QUAD_CurrentVersionRun_0075 {
  strings:
    $key_0075 = { 53 1a [2] 77 14 [2] 5c 38 [2] 72 1a [2] 66 01 [2] 69 1b [2] 77 06 [2] 75 07 [2] 6e 01 [2] 72 06 [2] 6e 29 }

  condition:
    any of them
}