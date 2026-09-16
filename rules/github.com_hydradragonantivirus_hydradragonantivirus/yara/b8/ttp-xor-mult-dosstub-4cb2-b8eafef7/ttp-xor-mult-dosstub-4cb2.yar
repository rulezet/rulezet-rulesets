rule TTP_XOR_MULT_DOSStub_4cb2 {
  strings:
    $key_4cb2 = { 18 da [2] 6c c2 [2] 2b c0 [2] 6c d1 [2] 22 dd [2] 2e d7 [2] 39 dc [2] 22 92 [2] 1f }

  condition:
    any of them
}