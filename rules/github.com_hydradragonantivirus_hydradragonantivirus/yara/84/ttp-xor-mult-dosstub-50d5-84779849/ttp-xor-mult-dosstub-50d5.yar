rule TTP_XOR_MULT_DOSStub_50d5 {
  strings:
    $key_50d5 = { 04 bd [2] 70 a5 [2] 37 a7 [2] 70 b6 [2] 3e ba [2] 32 b0 [2] 25 bb [2] 3e f5 [2] 03 }

  condition:
    any of them
}