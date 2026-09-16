rule TTP_XOR_MULT_DOSStub_1eb4 {
  strings:
    $key_1eb4 = { 4a dc [2] 3e c4 [2] 79 c6 [2] 3e d7 [2] 70 db [2] 7c d1 [2] 6b da [2] 70 94 [2] 4d }

  condition:
    any of them
}