rule TTP_XOR_MULT_DOSStub_1cb4 {
  strings:
    $key_1cb4 = { 48 dc [2] 3c c4 [2] 7b c6 [2] 3c d7 [2] 72 db [2] 7e d1 [2] 69 da [2] 72 94 [2] 4f }

  condition:
    any of them
}