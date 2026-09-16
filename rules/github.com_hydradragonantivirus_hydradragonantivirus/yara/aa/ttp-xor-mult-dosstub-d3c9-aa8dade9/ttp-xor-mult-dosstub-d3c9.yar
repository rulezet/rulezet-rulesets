rule TTP_XOR_MULT_DOSStub_d3c9 {
  strings:
    $key_d3c9 = { 87 a1 [2] f3 b9 [2] b4 bb [2] f3 aa [2] bd a6 [2] b1 ac [2] a6 a7 [2] bd e9 [2] 80 }

  condition:
    any of them
}