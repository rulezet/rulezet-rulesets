rule TTP_XOR_QUAD_CurrentVersionRun_2c66 {
  strings:
    $key_2c66 = { 7f 09 [2] 5b 07 [2] 70 2b [2] 5e 09 [2] 4a 12 [2] 45 08 [2] 5b 15 [2] 59 14 [2] 42 12 [2] 5e 15 [2] 42 3a }

  condition:
    any of them
}