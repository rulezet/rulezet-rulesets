rule TTP_XOR_MULT_DOSStub_87b0 {
  strings:
    $key_87b0 = { d3 d8 [2] a7 c0 [2] e0 c2 [2] a7 d3 [2] e9 df [2] e5 d5 [2] f2 de [2] e9 90 [2] d4 }

  condition:
    any of them
}