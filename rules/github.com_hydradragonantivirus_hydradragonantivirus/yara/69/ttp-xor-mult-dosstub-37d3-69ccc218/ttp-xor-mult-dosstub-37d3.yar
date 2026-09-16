rule TTP_XOR_MULT_DOSStub_37d3 {
  strings:
    $key_37d3 = { 63 bb [2] 17 a3 [2] 50 a1 [2] 17 b0 [2] 59 bc [2] 55 b6 [2] 42 bd [2] 59 f3 [2] 64 }

  condition:
    any of them
}