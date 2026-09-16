rule TTP_XOR_MULT_DOSStub_d0d5 {
  strings:
    $key_d0d5 = { 84 bd [2] f0 a5 [2] b7 a7 [2] f0 b6 [2] be ba [2] b2 b0 [2] a5 bb [2] be f5 [2] 83 }

  condition:
    any of them
}