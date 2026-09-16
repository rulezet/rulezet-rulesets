rule TTP_XOR_MULT_DOSStub_d5d3 {
  strings:
    $key_d5d3 = { 81 bb [2] f5 a3 [2] b2 a1 [2] f5 b0 [2] bb bc [2] b7 b6 [2] a0 bd [2] bb f3 [2] 86 }

  condition:
    any of them
}