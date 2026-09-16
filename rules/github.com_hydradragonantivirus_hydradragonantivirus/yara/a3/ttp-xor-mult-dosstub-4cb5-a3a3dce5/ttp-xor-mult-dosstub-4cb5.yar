rule TTP_XOR_MULT_DOSStub_4cb5 {
  strings:
    $key_4cb5 = { 18 dd [2] 6c c5 [2] 2b c7 [2] 6c d6 [2] 22 da [2] 2e d0 [2] 39 db [2] 22 95 [2] 1f }

  condition:
    any of them
}