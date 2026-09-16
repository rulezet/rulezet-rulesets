rule TTP_XOR_MULT_DOSStub_57d3 {
  strings:
    $key_57d3 = { 03 bb [2] 77 a3 [2] 30 a1 [2] 77 b0 [2] 39 bc [2] 35 b6 [2] 22 bd [2] 39 f3 [2] 04 }

  condition:
    any of them
}