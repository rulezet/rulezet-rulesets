rule TTP_XOR_MULT_DOSStub_d3c5 {
  strings:
    $key_d3c5 = { 87 ad [2] f3 b5 [2] b4 b7 [2] f3 a6 [2] bd aa [2] b1 a0 [2] a6 ab [2] bd e5 [2] 80 }

  condition:
    any of them
}