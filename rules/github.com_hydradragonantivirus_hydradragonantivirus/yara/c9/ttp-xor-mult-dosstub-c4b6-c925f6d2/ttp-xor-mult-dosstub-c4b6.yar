rule TTP_XOR_MULT_DOSStub_c4b6 {
  strings:
    $key_c4b6 = { 90 de [2] e4 c6 [2] a3 c4 [2] e4 d5 [2] aa d9 [2] a6 d3 [2] b1 d8 [2] aa 96 [2] 97 }

  condition:
    any of them
}