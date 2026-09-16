rule TTP_XOR_MULT_DOSStub_91d8 {
  strings:
    $key_91d8 = { c5 b0 [2] b1 a8 [2] f6 aa [2] b1 bb [2] ff b7 [2] f3 bd [2] e4 b6 [2] ff f8 [2] c2 }

  condition:
    any of them
}