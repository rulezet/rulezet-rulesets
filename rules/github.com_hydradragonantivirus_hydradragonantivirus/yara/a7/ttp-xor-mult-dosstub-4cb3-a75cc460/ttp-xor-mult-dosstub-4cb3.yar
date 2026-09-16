rule TTP_XOR_MULT_DOSStub_4cb3 {
  strings:
    $key_4cb3 = { 18 db [2] 6c c3 [2] 2b c1 [2] 6c d0 [2] 22 dc [2] 2e d6 [2] 39 dd [2] 22 93 [2] 1f }

  condition:
    any of them
}