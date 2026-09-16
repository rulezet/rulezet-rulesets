rule TTP_XOR_QUAD_CurrentVersionRun_5972 {
  strings:
    $key_5972 = { 0a 1d [2] 2e 13 [2] 05 3f [2] 2b 1d [2] 3f 06 [2] 30 1c [2] 2e 01 [2] 2c 00 [2] 37 06 [2] 2b 01 [2] 37 2e }

  condition:
    any of them
}