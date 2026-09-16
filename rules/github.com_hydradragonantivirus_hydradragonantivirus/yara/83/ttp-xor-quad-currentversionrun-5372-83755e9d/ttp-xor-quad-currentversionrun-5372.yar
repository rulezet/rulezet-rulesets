rule TTP_XOR_QUAD_CurrentVersionRun_5372 {
  strings:
    $key_5372 = { 00 1d [2] 24 13 [2] 0f 3f [2] 21 1d [2] 35 06 [2] 3a 1c [2] 24 01 [2] 26 00 [2] 3d 06 [2] 21 01 [2] 3d 2e }

  condition:
    any of them
}