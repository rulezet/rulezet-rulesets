rule TTP_XOR_MULT_DOSStub_67d3 {
  strings:
    $key_67d3 = { 33 bb [2] 47 a3 [2] 00 a1 [2] 47 b0 [2] 09 bc [2] 05 b6 [2] 12 bd [2] 09 f3 [2] 34 }

  condition:
    any of them
}