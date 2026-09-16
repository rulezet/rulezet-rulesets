rule TTP_XOR_MULT_DOSStub_4eb3 {
  strings:
    $key_4eb3 = { 1a db [2] 6e c3 [2] 29 c1 [2] 6e d0 [2] 20 dc [2] 2c d6 [2] 3b dd [2] 20 93 [2] 1d }

  condition:
    any of them
}