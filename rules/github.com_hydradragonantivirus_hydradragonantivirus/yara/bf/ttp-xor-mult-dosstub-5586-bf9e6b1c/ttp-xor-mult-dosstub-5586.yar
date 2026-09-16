rule TTP_XOR_MULT_DOSStub_5586 {
  strings:
    $key_5586 = { 01 ee [2] 75 f6 [2] 32 f4 [2] 75 e5 [2] 3b e9 [2] 37 e3 [2] 20 e8 [2] 3b a6 [2] 06 }

  condition:
    any of them
}