rule TTP_XOR_MULT_DOSStub_a7d9 {
  strings:
    $key_a7d9 = { f3 b1 [2] 87 a9 [2] c0 ab [2] 87 ba [2] c9 b6 [2] c5 bc [2] d2 b7 [2] c9 f9 [2] f4 }

  condition:
    any of them
}