rule TTP_XOR_QUAD_CurrentVersionRun_735b {
  strings:
    $key_735b = { 20 34 [2] 04 3a [2] 2f 16 [2] 01 34 [2] 15 2f [2] 1a 35 [2] 04 28 [2] 06 29 [2] 1d 2f [2] 01 28 [2] 1d 07 }

  condition:
    any of them
}