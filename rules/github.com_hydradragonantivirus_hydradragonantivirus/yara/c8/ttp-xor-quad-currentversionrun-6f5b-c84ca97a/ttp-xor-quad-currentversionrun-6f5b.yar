rule TTP_XOR_QUAD_CurrentVersionRun_6f5b {
  strings:
    $key_6f5b = { 3c 34 [2] 18 3a [2] 33 16 [2] 1d 34 [2] 09 2f [2] 06 35 [2] 18 28 [2] 1a 29 [2] 01 2f [2] 1d 28 [2] 01 07 }

  condition:
    any of them
}