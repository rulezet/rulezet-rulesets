rule TTP_XOR_MULT_DOSStub_4cb7 {
  strings:
    $key_4cb7 = { 18 df [2] 6c c7 [2] 2b c5 [2] 6c d4 [2] 22 d8 [2] 2e d2 [2] 39 d9 [2] 22 97 [2] 1f }

  condition:
    any of them
}