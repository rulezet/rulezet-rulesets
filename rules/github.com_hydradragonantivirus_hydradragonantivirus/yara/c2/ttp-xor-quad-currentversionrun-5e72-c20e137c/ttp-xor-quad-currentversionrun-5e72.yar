rule TTP_XOR_QUAD_CurrentVersionRun_5e72 {
  strings:
    $key_5e72 = { 0d 1d [2] 29 13 [2] 02 3f [2] 2c 1d [2] 38 06 [2] 37 1c [2] 29 01 [2] 2b 00 [2] 30 06 [2] 2c 01 [2] 30 2e }

  condition:
    any of them
}