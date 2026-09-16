rule TTP_XOR_MULT_DOSStub_98d8 {
  strings:
    $key_98d8 = { cc b0 [2] b8 a8 [2] ff aa [2] b8 bb [2] f6 b7 [2] fa bd [2] ed b6 [2] f6 f8 [2] cb }

  condition:
    any of them
}