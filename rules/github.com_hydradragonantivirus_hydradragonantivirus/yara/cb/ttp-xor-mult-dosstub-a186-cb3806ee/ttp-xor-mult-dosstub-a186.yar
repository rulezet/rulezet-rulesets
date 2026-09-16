rule TTP_XOR_MULT_DOSStub_a186 {
  strings:
    $key_a186 = { f5 ee [2] 81 f6 [2] c6 f4 [2] 81 e5 [2] cf e9 [2] c3 e3 [2] d4 e8 [2] cf a6 [2] f2 }

  condition:
    any of them
}