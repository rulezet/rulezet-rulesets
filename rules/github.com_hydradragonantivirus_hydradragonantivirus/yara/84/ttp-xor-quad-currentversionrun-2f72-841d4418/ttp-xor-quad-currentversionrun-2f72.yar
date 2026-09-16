rule TTP_XOR_QUAD_CurrentVersionRun_2f72 {
  strings:
    $key_2f72 = { 7c 1d [2] 58 13 [2] 73 3f [2] 5d 1d [2] 49 06 [2] 46 1c [2] 58 01 [2] 5a 00 [2] 41 06 [2] 5d 01 [2] 41 2e }

  condition:
    any of them
}