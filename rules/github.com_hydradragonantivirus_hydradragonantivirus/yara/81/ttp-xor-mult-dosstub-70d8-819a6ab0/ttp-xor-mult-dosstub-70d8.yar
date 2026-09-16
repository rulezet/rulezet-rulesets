rule TTP_XOR_MULT_DOSStub_70d8 {
  strings:
    $key_70d8 = { 24 b0 [2] 50 a8 [2] 17 aa [2] 50 bb [2] 1e b7 [2] 12 bd [2] 05 b6 [2] 1e f8 [2] 23 }

  condition:
    any of them
}