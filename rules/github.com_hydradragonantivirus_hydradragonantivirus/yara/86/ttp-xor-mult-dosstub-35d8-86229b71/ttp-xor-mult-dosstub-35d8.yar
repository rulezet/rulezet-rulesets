rule TTP_XOR_MULT_DOSStub_35d8 {
  strings:
    $key_35d8 = { 61 b0 [2] 15 a8 [2] 52 aa [2] 15 bb [2] 5b b7 [2] 57 bd [2] 40 b6 [2] 5b f8 [2] 66 }

  condition:
    any of them
}