rule TTP_XOR_MULT_DOSStub_7cb3 {
  strings:
    $key_7cb3 = { 28 db [2] 5c c3 [2] 1b c1 [2] 5c d0 [2] 12 dc [2] 1e d6 [2] 09 dd [2] 12 93 [2] 2f }

  condition:
    any of them
}