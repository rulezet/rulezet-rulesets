rule TTP_XOR_QUAD_CurrentVersionRun_5472 {
  strings:
    $key_5472 = { 07 1d [2] 23 13 [2] 08 3f [2] 26 1d [2] 32 06 [2] 3d 1c [2] 23 01 [2] 21 00 [2] 3a 06 [2] 26 01 [2] 3a 2e }

  condition:
    any of them
}