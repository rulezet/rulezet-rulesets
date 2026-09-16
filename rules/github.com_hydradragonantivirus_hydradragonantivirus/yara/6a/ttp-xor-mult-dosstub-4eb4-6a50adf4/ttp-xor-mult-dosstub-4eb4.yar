rule TTP_XOR_MULT_DOSStub_4eb4 {
  strings:
    $key_4eb4 = { 1a dc [2] 6e c4 [2] 29 c6 [2] 6e d7 [2] 20 db [2] 2c d1 [2] 3b da [2] 20 94 [2] 1d }

  condition:
    any of them
}