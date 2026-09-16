rule TTP_XOR_MULT_DOSStub_75b0 {
  strings:
    $key_75b0 = { 21 d8 [2] 55 c0 [2] 12 c2 [2] 55 d3 [2] 1b df [2] 17 d5 [2] 00 de [2] 1b 90 [2] 26 }

  condition:
    any of them
}