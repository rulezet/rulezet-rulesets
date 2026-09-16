rule TTP_XOR_MULT_DOSStub_7cb5 {
  strings:
    $key_7cb5 = { 28 dd [2] 5c c5 [2] 1b c7 [2] 5c d6 [2] 12 da [2] 1e d0 [2] 09 db [2] 12 95 [2] 2f }

  condition:
    any of them
}