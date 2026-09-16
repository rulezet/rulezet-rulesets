rule TTP_XOR_MULT_DOSStub_5cb7 {
  strings:
    $key_5cb7 = { 08 df [2] 7c c7 [2] 3b c5 [2] 7c d4 [2] 32 d8 [2] 3e d2 [2] 29 d9 [2] 32 97 [2] 0f }

  condition:
    any of them
}