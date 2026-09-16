rule TTP_XOR_MULT_DOSStub_52d8 {
  strings:
    $key_52d8 = { 06 b0 [2] 72 a8 [2] 35 aa [2] 72 bb [2] 3c b7 [2] 30 bd [2] 27 b6 [2] 3c f8 [2] 01 }

  condition:
    any of them
}