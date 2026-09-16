rule TTP_XOR_MULT_DOSStub_d3ce {
  strings:
    $key_d3ce = { 87 a6 [2] f3 be [2] b4 bc [2] f3 ad [2] bd a1 [2] b1 ab [2] a6 a0 [2] bd ee [2] 80 }

  condition:
    any of them
}