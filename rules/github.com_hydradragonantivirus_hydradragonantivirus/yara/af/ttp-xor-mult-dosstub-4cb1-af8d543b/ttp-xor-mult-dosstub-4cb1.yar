rule TTP_XOR_MULT_DOSStub_4cb1 {
  strings:
    $key_4cb1 = { 18 d9 [2] 6c c1 [2] 2b c3 [2] 6c d2 [2] 22 de [2] 2e d4 [2] 39 df [2] 22 91 [2] 1f }

  condition:
    any of them
}