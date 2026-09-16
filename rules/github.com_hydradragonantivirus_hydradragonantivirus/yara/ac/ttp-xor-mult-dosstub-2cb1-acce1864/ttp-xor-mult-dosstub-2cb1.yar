rule TTP_XOR_MULT_DOSStub_2cb1 {
  strings:
    $key_2cb1 = { 78 d9 [2] 0c c1 [2] 4b c3 [2] 0c d2 [2] 42 de [2] 4e d4 [2] 59 df [2] 42 91 [2] 7f }

  condition:
    any of them
}