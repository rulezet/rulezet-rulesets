rule TTP_XOR_QUAD_CurrentVersionRun_2d72 {
  strings:
    $key_2d72 = { 7e 1d [2] 5a 13 [2] 71 3f [2] 5f 1d [2] 4b 06 [2] 44 1c [2] 5a 01 [2] 58 00 [2] 43 06 [2] 5f 01 [2] 43 2e }

  condition:
    any of them
}