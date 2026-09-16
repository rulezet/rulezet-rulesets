rule TTP_XOR_MULT_DOSStub_d3dd {
  strings:
    $key_d3dd = { 87 b5 [2] f3 ad [2] b4 af [2] f3 be [2] bd b2 [2] b1 b8 [2] a6 b3 [2] bd fd [2] 80 }

  condition:
    any of them
}