rule TTP_XOR_MULT_DOSStub_87b9 {
  strings:
    $key_87b9 = { d3 d1 [2] a7 c9 [2] e0 cb [2] a7 da [2] e9 d6 [2] e5 dc [2] f2 d7 [2] e9 99 [2] d4 }

  condition:
    any of them
}