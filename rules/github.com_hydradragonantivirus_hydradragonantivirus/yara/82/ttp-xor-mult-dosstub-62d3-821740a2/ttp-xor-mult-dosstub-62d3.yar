rule TTP_XOR_MULT_DOSStub_62d3 {
  strings:
    $key_62d3 = { 36 bb [2] 42 a3 [2] 05 a1 [2] 42 b0 [2] 0c bc [2] 00 b6 [2] 17 bd [2] 0c f3 [2] 31 }

  condition:
    any of them
}