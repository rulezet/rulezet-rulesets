rule TTP_XOR_MULT_DOSStub_31d3 {
  strings:
    $key_31d3 = { 65 bb [2] 11 a3 [2] 56 a1 [2] 11 b0 [2] 5f bc [2] 53 b6 [2] 44 bd [2] 5f f3 [2] 62 }

  condition:
    any of them
}