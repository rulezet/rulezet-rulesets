rule TTP_XOR_MULT_DOSStub_02d8 {
  strings:
    $key_02d8 = { 56 b0 [2] 22 a8 [2] 65 aa [2] 22 bb [2] 6c b7 [2] 60 bd [2] 77 b6 [2] 6c f8 [2] 51 }

  condition:
    any of them
}