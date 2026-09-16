rule TTP_XOR_MULT_DOSStub_d3a0 {
  strings:
    $key_d3a0 = { 87 c8 [2] f3 d0 [2] b4 d2 [2] f3 c3 [2] bd cf [2] b1 c5 [2] a6 ce [2] bd 80 [2] 80 }

  condition:
    any of them
}