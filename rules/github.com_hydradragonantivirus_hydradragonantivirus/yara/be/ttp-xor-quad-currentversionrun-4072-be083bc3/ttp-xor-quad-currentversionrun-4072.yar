rule TTP_XOR_QUAD_CurrentVersionRun_4072 {
  strings:
    $key_4072 = { 13 1d [2] 37 13 [2] 1c 3f [2] 32 1d [2] 26 06 [2] 29 1c [2] 37 01 [2] 35 00 [2] 2e 06 [2] 32 01 [2] 2e 2e }

  condition:
    any of them
}