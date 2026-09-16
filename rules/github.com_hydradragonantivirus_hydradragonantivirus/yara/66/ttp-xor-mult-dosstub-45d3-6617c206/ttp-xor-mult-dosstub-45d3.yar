rule TTP_XOR_MULT_DOSStub_45d3 {
  strings:
    $key_45d3 = { 11 bb [2] 65 a3 [2] 22 a1 [2] 65 b0 [2] 2b bc [2] 27 b6 [2] 30 bd [2] 2b f3 [2] 16 }

  condition:
    any of them
}