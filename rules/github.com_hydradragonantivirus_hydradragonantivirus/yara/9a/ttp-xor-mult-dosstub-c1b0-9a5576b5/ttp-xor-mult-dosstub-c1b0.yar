rule TTP_XOR_MULT_DOSStub_c1b0 {
  strings:
    $key_c1b0 = { 95 d8 [2] e1 c0 [2] a6 c2 [2] e1 d3 [2] af df [2] a3 d5 [2] b4 de [2] af 90 [2] 92 }

  condition:
    any of them
}