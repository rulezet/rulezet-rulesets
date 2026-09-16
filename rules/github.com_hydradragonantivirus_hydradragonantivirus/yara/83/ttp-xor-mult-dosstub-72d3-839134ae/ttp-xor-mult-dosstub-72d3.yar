rule TTP_XOR_MULT_DOSStub_72d3 {
  strings:
    $key_72d3 = { 26 bb [2] 52 a3 [2] 15 a1 [2] 52 b0 [2] 1c bc [2] 10 b6 [2] 07 bd [2] 1c f3 [2] 21 }

  condition:
    any of them
}