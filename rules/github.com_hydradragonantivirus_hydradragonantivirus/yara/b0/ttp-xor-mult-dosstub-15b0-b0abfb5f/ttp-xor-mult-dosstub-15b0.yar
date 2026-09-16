rule TTP_XOR_MULT_DOSStub_15b0 {
  strings:
    $key_15b0 = { 41 d8 [2] 35 c0 [2] 72 c2 [2] 35 d3 [2] 7b df [2] 77 d5 [2] 60 de [2] 7b 90 [2] 46 }

  condition:
    any of them
}