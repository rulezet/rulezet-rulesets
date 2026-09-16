rule TTP_XOR_QUAD_CurrentVersionRun_2372 {
  strings:
    $key_2372 = { 70 1d [2] 54 13 [2] 7f 3f [2] 51 1d [2] 45 06 [2] 4a 1c [2] 54 01 [2] 56 00 [2] 4d 06 [2] 51 01 [2] 4d 2e }

  condition:
    any of them
}