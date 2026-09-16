rule TTP_XOR_MULT_DOSStub_c0b0 {
  strings:
    $key_c0b0 = { 94 d8 [2] e0 c0 [2] a7 c2 [2] e0 d3 [2] ae df [2] a2 d5 [2] b5 de [2] ae 90 [2] 93 }

  condition:
    any of them
}