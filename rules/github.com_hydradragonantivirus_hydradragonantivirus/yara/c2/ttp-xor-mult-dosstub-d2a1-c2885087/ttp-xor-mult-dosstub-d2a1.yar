rule TTP_XOR_MULT_DOSStub_d2a1 {
  strings:
    $key_d2a1 = { 86 c9 [2] f2 d1 [2] b5 d3 [2] f2 c2 [2] bc ce [2] b0 c4 [2] a7 cf [2] bc 81 [2] 81 }

  condition:
    any of them
}