rule TTP_XOR_MULT_DOSStub_10b0 {
  strings:
    $key_10b0 = { 44 d8 [2] 30 c0 [2] 77 c2 [2] 30 d3 [2] 7e df [2] 72 d5 [2] 65 de [2] 7e 90 [2] 43 }

  condition:
    any of them
}