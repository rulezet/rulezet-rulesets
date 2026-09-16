rule TTP_XOR_MULT_DOSStub_a0d5 {
  strings:
    $key_a0d5 = { f4 bd [2] 80 a5 [2] c7 a7 [2] 80 b6 [2] ce ba [2] c2 b0 [2] d5 bb [2] ce f5 [2] f3 }

  condition:
    any of them
}