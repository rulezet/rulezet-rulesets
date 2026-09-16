rule TTP_XOR_MULT_DOSStub_96d3 {
  strings:
    $key_96d3 = { c2 bb [2] b6 a3 [2] f1 a1 [2] b6 b0 [2] f8 bc [2] f4 b6 [2] e3 bd [2] f8 f3 [2] c5 }

  condition:
    any of them
}