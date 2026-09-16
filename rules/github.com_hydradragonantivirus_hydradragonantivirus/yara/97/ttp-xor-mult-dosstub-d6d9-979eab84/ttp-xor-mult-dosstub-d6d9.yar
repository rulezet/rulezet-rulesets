rule TTP_XOR_MULT_DOSStub_d6d9 {
  strings:
    $key_d6d9 = { 82 b1 [2] f6 a9 [2] b1 ab [2] f6 ba [2] b8 b6 [2] b4 bc [2] a3 b7 [2] b8 f9 [2] 85 }

  condition:
    any of them
}