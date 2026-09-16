rule TTP_XOR_MULT_DOSStub_a1c0 {
  strings:
    $key_a1c0 = { f5 a8 [2] 81 b0 [2] c6 b2 [2] 81 a3 [2] cf af [2] c3 a5 [2] d4 ae [2] cf e0 [2] f2 }

  condition:
    any of them
}