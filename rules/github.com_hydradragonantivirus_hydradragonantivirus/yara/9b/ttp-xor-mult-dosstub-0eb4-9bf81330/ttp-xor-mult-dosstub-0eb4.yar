rule TTP_XOR_MULT_DOSStub_0eb4 {
  strings:
    $key_0eb4 = { 5a dc [2] 2e c4 [2] 69 c6 [2] 2e d7 [2] 60 db [2] 6c d1 [2] 7b da [2] 60 94 [2] 5d }

  condition:
    any of them
}