rule TTP_XOR_QUAD_CurrentVersionRun_2272 {
  strings:
    $key_2272 = { 71 1d [2] 55 13 [2] 7e 3f [2] 50 1d [2] 44 06 [2] 4b 1c [2] 55 01 [2] 57 00 [2] 4c 06 [2] 50 01 [2] 4c 2e }

  condition:
    any of them
}