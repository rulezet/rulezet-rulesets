rule TTP_XOR_MULT_DOSStub_5cb1 {
  strings:
    $key_5cb1 = { 08 d9 [2] 7c c1 [2] 3b c3 [2] 7c d2 [2] 32 de [2] 3e d4 [2] 29 df [2] 32 91 [2] 0f }

  condition:
    any of them
}