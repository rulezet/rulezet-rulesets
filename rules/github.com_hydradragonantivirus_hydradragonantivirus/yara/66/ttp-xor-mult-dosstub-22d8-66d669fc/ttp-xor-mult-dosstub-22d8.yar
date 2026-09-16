rule TTP_XOR_MULT_DOSStub_22d8 {
  strings:
    $key_22d8 = { 76 b0 [2] 02 a8 [2] 45 aa [2] 02 bb [2] 4c b7 [2] 40 bd [2] 57 b6 [2] 4c f8 [2] 71 }

  condition:
    any of them
}