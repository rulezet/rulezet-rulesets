rule TTP_XOR_MULT_DOSStub_1cb3 {
  strings:
    $key_1cb3 = { 48 db [2] 3c c3 [2] 7b c1 [2] 3c d0 [2] 72 dc [2] 7e d6 [2] 69 dd [2] 72 93 [2] 4f }

  condition:
    any of them
}