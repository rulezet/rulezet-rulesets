rule TTP_XOR_MULT_DOSStub_3cb1 {
  strings:
    $key_3cb1 = { 68 d9 [2] 1c c1 [2] 5b c3 [2] 1c d2 [2] 52 de [2] 5e d4 [2] 49 df [2] 52 91 [2] 6f }

  condition:
    any of them
}