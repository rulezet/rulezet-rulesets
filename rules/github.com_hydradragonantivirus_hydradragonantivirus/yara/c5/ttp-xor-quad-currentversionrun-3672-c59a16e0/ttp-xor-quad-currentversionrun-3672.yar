rule TTP_XOR_QUAD_CurrentVersionRun_3672 {
  strings:
    $key_3672 = { 65 1d [2] 41 13 [2] 6a 3f [2] 44 1d [2] 50 06 [2] 5f 1c [2] 41 01 [2] 43 00 [2] 58 06 [2] 44 01 [2] 58 2e }

  condition:
    any of them
}