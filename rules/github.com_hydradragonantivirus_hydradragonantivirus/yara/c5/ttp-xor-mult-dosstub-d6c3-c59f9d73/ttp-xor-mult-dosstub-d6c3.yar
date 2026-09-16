rule TTP_XOR_MULT_DOSStub_d6c3 {
  strings:
    $key_d6c3 = { 82 ab [2] f6 b3 [2] b1 b1 [2] f6 a0 [2] b8 ac [2] b4 a6 [2] a3 ad [2] b8 e3 [2] 85 }

  condition:
    any of them
}