rule TTP_XOR_MULT_DOSStub_91d3 {
  strings:
    $key_91d3 = { c5 bb [2] b1 a3 [2] f6 a1 [2] b1 b0 [2] ff bc [2] f3 b6 [2] e4 bd [2] ff f3 [2] c2 }

  condition:
    any of them
}