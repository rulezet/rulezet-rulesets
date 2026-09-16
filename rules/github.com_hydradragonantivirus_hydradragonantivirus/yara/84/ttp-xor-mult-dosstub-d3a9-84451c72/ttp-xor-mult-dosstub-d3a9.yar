rule TTP_XOR_MULT_DOSStub_d3a9 {
  strings:
    $key_d3a9 = { 87 c1 [2] f3 d9 [2] b4 db [2] f3 ca [2] bd c6 [2] b1 cc [2] a6 c7 [2] bd 89 [2] 80 }

  condition:
    any of them
}