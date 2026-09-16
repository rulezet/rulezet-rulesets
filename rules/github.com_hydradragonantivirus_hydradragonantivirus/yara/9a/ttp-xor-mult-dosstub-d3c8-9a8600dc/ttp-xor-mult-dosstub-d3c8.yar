rule TTP_XOR_MULT_DOSStub_d3c8 {
  strings:
    $key_d3c8 = { 87 a0 [2] f3 b8 [2] b4 ba [2] f3 ab [2] bd a7 [2] b1 ad [2] a6 a6 [2] bd e8 [2] 80 }

  condition:
    any of them
}