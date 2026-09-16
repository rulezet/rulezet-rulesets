rule TTP_XOR_MULT_DOSStub_d189 {
  strings:
    $key_d189 = { 85 e1 [2] f1 f9 [2] b6 fb [2] f1 ea [2] bf e6 [2] b3 ec [2] a4 e7 [2] bf a9 [2] 82 }

  condition:
    any of them
}