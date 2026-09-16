rule TTP_XOR_MULT_DOSStub_c3b0 {
  strings:
    $key_c3b0 = { 97 d8 [2] e3 c0 [2] a4 c2 [2] e3 d3 [2] ad df [2] a1 d5 [2] b6 de [2] ad 90 [2] 90 }

  condition:
    any of them
}