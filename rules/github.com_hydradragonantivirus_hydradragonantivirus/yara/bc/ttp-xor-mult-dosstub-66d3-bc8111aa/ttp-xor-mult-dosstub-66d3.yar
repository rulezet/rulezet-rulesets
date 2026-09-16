rule TTP_XOR_MULT_DOSStub_66d3 {
  strings:
    $key_66d3 = { 32 bb [2] 46 a3 [2] 01 a1 [2] 46 b0 [2] 08 bc [2] 04 b6 [2] 13 bd [2] 08 f3 [2] 35 }

  condition:
    any of them
}