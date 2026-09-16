rule TTP_XOR_MULT_DOSStub_a7c6 {
  strings:
    $key_a7c6 = { f3 ae [2] 87 b6 [2] c0 b4 [2] 87 a5 [2] c9 a9 [2] c5 a3 [2] d2 a8 [2] c9 e6 [2] f4 }

  condition:
    any of them
}