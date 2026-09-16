rule TTP_XOR_MULT_DOSStub_04d3 {
  strings:
    $key_04d3 = { 50 bb [2] 24 a3 [2] 63 a1 [2] 24 b0 [2] 6a bc [2] 66 b6 [2] 71 bd [2] 6a f3 [2] 57 }

  condition:
    any of them
}