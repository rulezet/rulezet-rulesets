rule TTP_XOR_MULT_DOSStub_96d8 {
  strings:
    $key_96d8 = { c2 b0 [2] b6 a8 [2] f1 aa [2] b6 bb [2] f8 b7 [2] f4 bd [2] e3 b6 [2] f8 f8 [2] c5 }

  condition:
    any of them
}