rule TTP_XOR_MULT_DOSStub_42d5 {
  strings:
    $key_42d5 = { 16 bd [2] 62 a5 [2] 25 a7 [2] 62 b6 [2] 2c ba [2] 20 b0 [2] 37 bb [2] 2c f5 [2] 11 }

  condition:
    any of them
}