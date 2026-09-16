rule TTP_XOR_MULT_DOSStub_01d5 {
  strings:
    $key_01d5 = { 55 bd [2] 21 a5 [2] 66 a7 [2] 21 b6 [2] 6f ba [2] 63 b0 [2] 74 bb [2] 6f f5 [2] 52 }

  condition:
    any of them
}