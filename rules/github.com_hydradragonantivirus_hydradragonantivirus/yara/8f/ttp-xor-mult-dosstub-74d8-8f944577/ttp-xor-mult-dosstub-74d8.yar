rule TTP_XOR_MULT_DOSStub_74d8 {
  strings:
    $key_74d8 = { 20 b0 [2] 54 a8 [2] 13 aa [2] 54 bb [2] 1a b7 [2] 16 bd [2] 01 b6 [2] 1a f8 [2] 27 }

  condition:
    any of them
}