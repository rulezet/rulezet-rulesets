rule TTP_XOR_MULT_DOSStub_20d5 {
  strings:
    $key_20d5 = { 74 bd [2] 00 a5 [2] 47 a7 [2] 00 b6 [2] 4e ba [2] 42 b0 [2] 55 bb [2] 4e f5 [2] 73 }

  condition:
    any of them
}