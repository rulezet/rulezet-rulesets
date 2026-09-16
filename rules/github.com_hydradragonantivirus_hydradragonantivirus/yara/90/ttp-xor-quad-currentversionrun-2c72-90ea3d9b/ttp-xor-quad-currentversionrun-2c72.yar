rule TTP_XOR_QUAD_CurrentVersionRun_2c72 {
  strings:
    $key_2c72 = { 7f 1d [2] 5b 13 [2] 70 3f [2] 5e 1d [2] 4a 06 [2] 45 1c [2] 5b 01 [2] 59 00 [2] 42 06 [2] 5e 01 [2] 42 2e }

  condition:
    any of them
}