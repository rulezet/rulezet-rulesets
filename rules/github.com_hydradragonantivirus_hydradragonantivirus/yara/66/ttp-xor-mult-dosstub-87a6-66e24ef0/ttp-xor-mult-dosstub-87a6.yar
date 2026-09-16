rule TTP_XOR_MULT_DOSStub_87a6 {
  strings:
    $key_87a6 = { d3 ce [2] a7 d6 [2] e0 d4 [2] a7 c5 [2] e9 c9 [2] e5 c3 [2] f2 c8 [2] e9 86 [2] d4 }

  condition:
    any of them
}