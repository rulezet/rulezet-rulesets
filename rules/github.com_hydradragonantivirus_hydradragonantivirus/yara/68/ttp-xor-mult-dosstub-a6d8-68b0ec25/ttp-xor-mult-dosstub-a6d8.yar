rule TTP_XOR_MULT_DOSStub_a6d8 {
  strings:
    $key_a6d8 = { f2 b0 [2] 86 a8 [2] c1 aa [2] 86 bb [2] c8 b7 [2] c4 bd [2] d3 b6 [2] c8 f8 [2] f5 }

  condition:
    any of them
}