rule TTP_XOR_MULT_DOSStub_f2d3 {
  strings:
    $key_f2d3 = { a6 bb [2] d2 a3 [2] 95 a1 [2] d2 b0 [2] 9c bc [2] 90 b6 [2] 87 bd [2] 9c f3 [2] a1 }

  condition:
    any of them
}