rule TTP_XOR_MULT_DOSStub_20d3 {
  strings:
    $key_20d3 = { 74 bb [2] 00 a3 [2] 47 a1 [2] 00 b0 [2] 4e bc [2] 42 b6 [2] 55 bd [2] 4e f3 [2] 73 }

  condition:
    any of them
}