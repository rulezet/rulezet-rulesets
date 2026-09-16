rule TTP_XOR_MULT_DOSStub_d3a4 {
  strings:
    $key_d3a4 = { 87 cc [2] f3 d4 [2] b4 d6 [2] f3 c7 [2] bd cb [2] b1 c1 [2] a6 ca [2] bd 84 [2] 80 }

  condition:
    any of them
}