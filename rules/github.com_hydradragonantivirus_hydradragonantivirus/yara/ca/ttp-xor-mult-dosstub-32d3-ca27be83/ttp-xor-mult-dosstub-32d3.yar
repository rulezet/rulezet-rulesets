rule TTP_XOR_MULT_DOSStub_32d3 {
  strings:
    $key_32d3 = { 66 bb [2] 12 a3 [2] 55 a1 [2] 12 b0 [2] 5c bc [2] 50 b6 [2] 47 bd [2] 5c f3 [2] 61 }

  condition:
    any of them
}