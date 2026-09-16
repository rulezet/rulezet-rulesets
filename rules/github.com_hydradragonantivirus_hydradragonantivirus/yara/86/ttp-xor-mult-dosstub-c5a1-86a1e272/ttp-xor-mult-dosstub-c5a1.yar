rule TTP_XOR_MULT_DOSStub_c5a1 {
  strings:
    $key_c5a1 = { 91 c9 [2] e5 d1 [2] a2 d3 [2] e5 c2 [2] ab ce [2] a7 c4 [2] b0 cf [2] ab 81 [2] 96 }

  condition:
    any of them
}