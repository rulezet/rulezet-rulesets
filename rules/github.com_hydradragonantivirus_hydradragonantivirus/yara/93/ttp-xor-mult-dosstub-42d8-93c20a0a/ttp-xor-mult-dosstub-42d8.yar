rule TTP_XOR_MULT_DOSStub_42d8 {
  strings:
    $key_42d8 = { 16 b0 [2] 62 a8 [2] 25 aa [2] 62 bb [2] 2c b7 [2] 20 bd [2] 37 b6 [2] 2c f8 [2] 11 }

  condition:
    any of them
}