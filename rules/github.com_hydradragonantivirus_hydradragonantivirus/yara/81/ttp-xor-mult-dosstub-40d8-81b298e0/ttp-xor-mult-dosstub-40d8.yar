rule TTP_XOR_MULT_DOSStub_40d8 {
  strings:
    $key_40d8 = { 14 b0 [2] 60 a8 [2] 27 aa [2] 60 bb [2] 2e b7 [2] 22 bd [2] 35 b6 [2] 2e f8 [2] 13 }

  condition:
    any of them
}