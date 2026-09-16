rule TTP_XOR_MULT_DOSStub_01d3 {
  strings:
    $key_01d3 = { 55 bb [2] 21 a3 [2] 66 a1 [2] 21 b0 [2] 6f bc [2] 63 b6 [2] 74 bd [2] 6f f3 [2] 52 }

  condition:
    any of them
}