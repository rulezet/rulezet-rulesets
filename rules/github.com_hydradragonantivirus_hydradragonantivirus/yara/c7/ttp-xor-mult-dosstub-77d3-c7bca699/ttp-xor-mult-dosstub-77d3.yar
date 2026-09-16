rule TTP_XOR_MULT_DOSStub_77d3 {
  strings:
    $key_77d3 = { 23 bb [2] 57 a3 [2] 10 a1 [2] 57 b0 [2] 19 bc [2] 15 b6 [2] 02 bd [2] 19 f3 [2] 24 }

  condition:
    any of them
}