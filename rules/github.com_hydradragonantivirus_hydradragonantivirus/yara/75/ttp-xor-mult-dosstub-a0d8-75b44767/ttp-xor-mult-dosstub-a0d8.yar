rule TTP_XOR_MULT_DOSStub_a0d8 {
  strings:
    $key_a0d8 = { f4 b0 [2] 80 a8 [2] c7 aa [2] 80 bb [2] ce b7 [2] c2 bd [2] d5 b6 [2] ce f8 [2] f3 }

  condition:
    any of them
}