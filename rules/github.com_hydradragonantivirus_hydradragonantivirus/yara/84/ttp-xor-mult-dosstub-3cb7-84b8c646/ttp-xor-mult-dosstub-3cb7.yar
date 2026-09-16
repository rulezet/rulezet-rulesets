rule TTP_XOR_MULT_DOSStub_3cb7 {
  strings:
    $key_3cb7 = { 68 df [2] 1c c7 [2] 5b c5 [2] 1c d4 [2] 52 d8 [2] 5e d2 [2] 49 d9 [2] 52 97 [2] 6f }

  condition:
    any of them
}