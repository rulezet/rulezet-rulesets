rule TTP_XOR_MULT_DOSStub_d3d8 {
  strings:
    $key_d3d8 = { 87 b0 [2] f3 a8 [2] b4 aa [2] f3 bb [2] bd b7 [2] b1 bd [2] a6 b6 [2] bd f8 [2] 80 }

  condition:
    any of them
}