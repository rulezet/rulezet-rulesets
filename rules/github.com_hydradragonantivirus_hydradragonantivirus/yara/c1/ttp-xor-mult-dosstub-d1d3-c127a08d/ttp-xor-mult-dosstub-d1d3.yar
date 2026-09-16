rule TTP_XOR_MULT_DOSStub_d1d3 {
  strings:
    $key_d1d3 = { 85 bb [2] f1 a3 [2] b6 a1 [2] f1 b0 [2] bf bc [2] b3 b6 [2] a4 bd [2] bf f3 [2] 82 }

  condition:
    any of them
}