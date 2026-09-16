rule TTP_XOR_MULT_DOSStub_60d5 {
  strings:
    $key_60d5 = { 34 bd [2] 40 a5 [2] 07 a7 [2] 40 b6 [2] 0e ba [2] 02 b0 [2] 15 bb [2] 0e f5 [2] 33 }

  condition:
    any of them
}