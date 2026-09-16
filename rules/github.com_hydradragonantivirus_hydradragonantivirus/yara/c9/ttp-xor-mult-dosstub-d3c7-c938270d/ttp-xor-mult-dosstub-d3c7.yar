rule TTP_XOR_MULT_DOSStub_d3c7 {
  strings:
    $key_d3c7 = { 87 af [2] f3 b7 [2] b4 b5 [2] f3 a4 [2] bd a8 [2] b1 a2 [2] a6 a9 [2] bd e7 [2] 80 }

  condition:
    any of them
}