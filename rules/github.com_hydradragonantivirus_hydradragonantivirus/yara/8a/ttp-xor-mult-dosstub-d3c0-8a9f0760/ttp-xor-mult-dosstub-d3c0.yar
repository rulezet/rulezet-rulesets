rule TTP_XOR_MULT_DOSStub_d3c0 {
  strings:
    $key_d3c0 = { 87 a8 [2] f3 b0 [2] b4 b2 [2] f3 a3 [2] bd af [2] b1 a5 [2] a6 ae [2] bd e0 [2] 80 }

  condition:
    any of them
}