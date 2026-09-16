rule TTP_XOR_MULT_DOSStub_63d3 {
  strings:
    $key_63d3 = { 37 bb [2] 43 a3 [2] 04 a1 [2] 43 b0 [2] 0d bc [2] 01 b6 [2] 16 bd [2] 0d f3 [2] 30 }

  condition:
    any of them
}