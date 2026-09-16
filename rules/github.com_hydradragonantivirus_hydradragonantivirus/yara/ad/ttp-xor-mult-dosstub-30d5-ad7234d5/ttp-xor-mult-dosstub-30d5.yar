rule TTP_XOR_MULT_DOSStub_30d5 {
  strings:
    $key_30d5 = { 64 bd [2] 10 a5 [2] 57 a7 [2] 10 b6 [2] 5e ba [2] 52 b0 [2] 45 bb [2] 5e f5 [2] 63 }

  condition:
    any of them
}