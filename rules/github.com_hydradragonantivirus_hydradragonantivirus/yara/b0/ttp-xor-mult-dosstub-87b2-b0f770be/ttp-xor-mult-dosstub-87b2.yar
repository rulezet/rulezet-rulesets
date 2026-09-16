rule TTP_XOR_MULT_DOSStub_87b2 {
  strings:
    $key_87b2 = { d3 da [2] a7 c2 [2] e0 c0 [2] a7 d1 [2] e9 dd [2] e5 d7 [2] f2 dc [2] e9 92 [2] d4 }

  condition:
    any of them
}