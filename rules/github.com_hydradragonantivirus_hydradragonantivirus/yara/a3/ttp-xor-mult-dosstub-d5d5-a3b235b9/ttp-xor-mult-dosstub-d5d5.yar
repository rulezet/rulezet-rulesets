rule TTP_XOR_MULT_DOSStub_d5d5 {
  strings:
    $key_d5d5 = { 81 bd [2] f5 a5 [2] b2 a7 [2] f5 b6 [2] bb ba [2] b7 b0 [2] a0 bb [2] bb f5 [2] 86 }

  condition:
    any of them
}