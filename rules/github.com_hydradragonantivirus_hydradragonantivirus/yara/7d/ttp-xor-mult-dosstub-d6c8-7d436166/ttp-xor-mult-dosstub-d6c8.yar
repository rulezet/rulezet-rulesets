rule TTP_XOR_MULT_DOSStub_d6c8 {
  strings:
    $key_d6c8 = { 82 a0 [2] f6 b8 [2] b1 ba [2] f6 ab [2] b8 a7 [2] b4 ad [2] a3 a6 [2] b8 e8 [2] 85 }

  condition:
    any of them
}