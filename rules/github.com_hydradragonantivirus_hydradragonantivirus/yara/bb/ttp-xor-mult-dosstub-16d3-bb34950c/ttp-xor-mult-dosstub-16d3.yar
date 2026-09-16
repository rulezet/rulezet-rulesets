rule TTP_XOR_MULT_DOSStub_16d3 {
  strings:
    $key_16d3 = { 42 bb [2] 36 a3 [2] 71 a1 [2] 36 b0 [2] 78 bc [2] 74 b6 [2] 63 bd [2] 78 f3 [2] 45 }

  condition:
    any of them
}