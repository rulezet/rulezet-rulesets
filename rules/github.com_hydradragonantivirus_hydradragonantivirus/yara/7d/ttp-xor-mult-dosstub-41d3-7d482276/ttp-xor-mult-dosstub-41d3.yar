rule TTP_XOR_MULT_DOSStub_41d3 {
  strings:
    $key_41d3 = { 15 bb [2] 61 a3 [2] 26 a1 [2] 61 b0 [2] 2f bc [2] 23 b6 [2] 34 bd [2] 2f f3 [2] 12 }

  condition:
    any of them
}