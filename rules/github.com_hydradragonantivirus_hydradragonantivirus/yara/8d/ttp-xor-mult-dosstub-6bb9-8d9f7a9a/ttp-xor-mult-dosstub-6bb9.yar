rule TTP_XOR_MULT_DOSStub_6bb9 {
  strings:
    $key_6bb9 = { 3f d1 [2] 4b c9 [2] 0c cb [2] 4b da [2] 05 d6 [2] 09 dc [2] 1e d7 [2] 05 99 [2] 38 }

  condition:
    any of them
}