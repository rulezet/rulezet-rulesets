rule TTP_XOR_MULT_DOSStub_42d3 {
  strings:
    $key_42d3 = { 16 bb [2] 62 a3 [2] 25 a1 [2] 62 b0 [2] 2c bc [2] 20 b6 [2] 37 bd [2] 2c f3 [2] 11 }

  condition:
    any of them
}