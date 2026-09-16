rule TTP_XOR_MULT_DOSStub_56d3 {
  strings:
    $key_56d3 = { 02 bb [2] 76 a3 [2] 31 a1 [2] 76 b0 [2] 38 bc [2] 34 b6 [2] 23 bd [2] 38 f3 [2] 05 }

  condition:
    any of them
}