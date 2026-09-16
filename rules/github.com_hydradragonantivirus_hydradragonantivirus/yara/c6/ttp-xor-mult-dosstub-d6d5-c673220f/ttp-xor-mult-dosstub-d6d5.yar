rule TTP_XOR_MULT_DOSStub_d6d5 {
  strings:
    $key_d6d5 = { 82 bd [2] f6 a5 [2] b1 a7 [2] f6 b6 [2] b8 ba [2] b4 b0 [2] a3 bb [2] b8 f5 [2] 85 }

  condition:
    any of them
}