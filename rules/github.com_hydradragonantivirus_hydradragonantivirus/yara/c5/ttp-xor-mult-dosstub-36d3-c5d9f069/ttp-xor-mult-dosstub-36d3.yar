rule TTP_XOR_MULT_DOSStub_36d3 {
  strings:
    $key_36d3 = { 62 bb [2] 16 a3 [2] 51 a1 [2] 16 b0 [2] 58 bc [2] 54 b6 [2] 43 bd [2] 58 f3 [2] 65 }

  condition:
    any of them
}