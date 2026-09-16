rule TTP_XOR_MULT_DOSStub_52d3 {
  strings:
    $key_52d3 = { 06 bb [2] 72 a3 [2] 35 a1 [2] 72 b0 [2] 3c bc [2] 30 b6 [2] 27 bd [2] 3c f3 [2] 01 }

  condition:
    any of them
}