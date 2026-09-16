rule TTP_XOR_MULT_DOSStub_4586 {
  strings:
    $key_4586 = { 11 ee [2] 65 f6 [2] 22 f4 [2] 65 e5 [2] 2b e9 [2] 27 e3 [2] 30 e8 [2] 2b a6 [2] 16 }

  condition:
    any of them
}