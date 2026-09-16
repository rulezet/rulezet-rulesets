rule TTP_XOR_MULT_DOSStub_54d8 {
  strings:
    $key_54d8 = { 00 b0 [2] 74 a8 [2] 33 aa [2] 74 bb [2] 3a b7 [2] 36 bd [2] 21 b6 [2] 3a f8 [2] 07 }

  condition:
    any of them
}