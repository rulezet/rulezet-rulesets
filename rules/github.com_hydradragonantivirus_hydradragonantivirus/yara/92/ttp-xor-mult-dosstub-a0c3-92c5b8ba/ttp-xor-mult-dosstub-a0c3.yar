rule TTP_XOR_MULT_DOSStub_a0c3 {
  strings:
    $key_a0c3 = { f4 ab [2] 80 b3 [2] c7 b1 [2] 80 a0 [2] ce ac [2] c2 a6 [2] d5 ad [2] ce e3 [2] f3 }

  condition:
    any of them
}