rule TTP_XOR_MULT_DOSStub_d7d6 {
  strings:
    $key_d7d6 = { 83 be [2] f7 a6 [2] b0 a4 [2] f7 b5 [2] b9 b9 [2] b5 b3 [2] a2 b8 [2] b9 f6 [2] 84 }

  condition:
    any of them
}