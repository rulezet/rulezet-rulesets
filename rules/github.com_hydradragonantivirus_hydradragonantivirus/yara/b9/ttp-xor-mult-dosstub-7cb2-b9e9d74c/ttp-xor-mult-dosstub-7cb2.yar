rule TTP_XOR_MULT_DOSStub_7cb2 {
  strings:
    $key_7cb2 = { 28 da [2] 5c c2 [2] 1b c0 [2] 5c d1 [2] 12 dd [2] 1e d7 [2] 09 dc [2] 12 92 [2] 2f }

  condition:
    any of them
}