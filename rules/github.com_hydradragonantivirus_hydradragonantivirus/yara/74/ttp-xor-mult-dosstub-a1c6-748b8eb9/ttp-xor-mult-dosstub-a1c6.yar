rule TTP_XOR_MULT_DOSStub_a1c6 {
  strings:
    $key_a1c6 = { f5 ae [2] 81 b6 [2] c6 b4 [2] 81 a5 [2] cf a9 [2] c3 a3 [2] d4 a8 [2] cf e6 [2] f2 }

  condition:
    any of them
}