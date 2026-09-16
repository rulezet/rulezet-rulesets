rule TTP_XOR_MULT_DOSStub_49d8 {
  strings:
    $key_49d8 = { 1d b0 [2] 69 a8 [2] 2e aa [2] 69 bb [2] 27 b7 [2] 2b bd [2] 3c b6 [2] 27 f8 [2] 1a }

  condition:
    any of them
}