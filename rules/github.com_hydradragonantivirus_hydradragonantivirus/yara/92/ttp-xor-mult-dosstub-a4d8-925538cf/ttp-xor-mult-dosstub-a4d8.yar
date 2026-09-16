rule TTP_XOR_MULT_DOSStub_a4d8 {
  strings:
    $key_a4d8 = { f0 b0 [2] 84 a8 [2] c3 aa [2] 84 bb [2] ca b7 [2] c6 bd [2] d1 b6 [2] ca f8 [2] f7 }

  condition:
    any of them
}