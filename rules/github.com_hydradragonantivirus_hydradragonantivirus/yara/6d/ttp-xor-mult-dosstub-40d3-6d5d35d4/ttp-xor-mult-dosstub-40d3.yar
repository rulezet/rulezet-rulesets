rule TTP_XOR_MULT_DOSStub_40d3 {
  strings:
    $key_40d3 = { 14 bb [2] 60 a3 [2] 27 a1 [2] 60 b0 [2] 2e bc [2] 22 b6 [2] 35 bd [2] 2e f3 [2] 13 }

  condition:
    any of them
}