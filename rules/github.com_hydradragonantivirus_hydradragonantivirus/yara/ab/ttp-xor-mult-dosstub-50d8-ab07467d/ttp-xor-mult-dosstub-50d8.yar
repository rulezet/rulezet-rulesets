rule TTP_XOR_MULT_DOSStub_50d8 {
  strings:
    $key_50d8 = { 04 b0 [2] 70 a8 [2] 37 aa [2] 70 bb [2] 3e b7 [2] 32 bd [2] 25 b6 [2] 3e f8 [2] 03 }

  condition:
    any of them
}