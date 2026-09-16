rule TTP_XOR_MULT_DOSStub_33d3 {
  strings:
    $key_33d3 = { 67 bb [2] 13 a3 [2] 54 a1 [2] 13 b0 [2] 5d bc [2] 51 b6 [2] 46 bd [2] 5d f3 [2] 60 }

  condition:
    any of them
}