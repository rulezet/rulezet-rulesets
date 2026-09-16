rule TTP_XOR_MULT_DOSStub_02d3 {
  strings:
    $key_02d3 = { 56 bb [2] 22 a3 [2] 65 a1 [2] 22 b0 [2] 6c bc [2] 60 b6 [2] 77 bd [2] 6c f3 [2] 51 }

  condition:
    any of them
}