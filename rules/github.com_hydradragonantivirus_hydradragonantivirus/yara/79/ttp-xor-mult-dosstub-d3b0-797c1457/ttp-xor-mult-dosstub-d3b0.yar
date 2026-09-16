rule TTP_XOR_MULT_DOSStub_d3b0 {
  strings:
    $key_d3b0 = { 87 d8 [2] f3 c0 [2] b4 c2 [2] f3 d3 [2] bd df [2] b1 d5 [2] a6 de [2] bd 90 [2] 80 }

  condition:
    any of them
}