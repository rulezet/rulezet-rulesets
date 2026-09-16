rule TTP_XOR_MULT_DOSStub_4cb4 {
  strings:
    $key_4cb4 = { 18 dc [2] 6c c4 [2] 2b c6 [2] 6c d7 [2] 22 db [2] 2e d1 [2] 39 da [2] 22 94 [2] 1f }

  condition:
    any of them
}