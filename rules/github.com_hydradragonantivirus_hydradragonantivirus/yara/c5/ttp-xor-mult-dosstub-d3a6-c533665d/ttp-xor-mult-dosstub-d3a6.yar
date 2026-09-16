rule TTP_XOR_MULT_DOSStub_d3a6 {
  strings:
    $key_d3a6 = { 87 ce [2] f3 d6 [2] b4 d4 [2] f3 c5 [2] bd c9 [2] b1 c3 [2] a6 c8 [2] bd 86 [2] 80 }

  condition:
    any of them
}