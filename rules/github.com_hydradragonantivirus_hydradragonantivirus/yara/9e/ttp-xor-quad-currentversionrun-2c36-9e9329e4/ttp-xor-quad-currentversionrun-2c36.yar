rule TTP_XOR_QUAD_CurrentVersionRun_2c36 {
  strings:
    $key_2c36 = { 7f 59 [2] 5b 57 [2] 70 7b [2] 5e 59 [2] 4a 42 [2] 45 58 [2] 5b 45 [2] 59 44 [2] 42 42 [2] 5e 45 [2] 42 6a }

  condition:
    any of them
}