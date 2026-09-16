rule TTP_XOR_MULT_DOSStub_a0d3 {
  strings:
    $key_a0d3 = { f4 bb [2] 80 a3 [2] c7 a1 [2] 80 b0 [2] ce bc [2] c2 b6 [2] d5 bd [2] ce f3 [2] f3 }

  condition:
    any of them
}