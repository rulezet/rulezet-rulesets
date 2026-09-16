rule TTP_XOR_MULT_DOSStub_7cb1 {
  strings:
    $key_7cb1 = { 28 d9 [2] 5c c1 [2] 1b c3 [2] 5c d2 [2] 12 de [2] 1e d4 [2] 09 df [2] 12 91 [2] 2f }

  condition:
    any of them
}