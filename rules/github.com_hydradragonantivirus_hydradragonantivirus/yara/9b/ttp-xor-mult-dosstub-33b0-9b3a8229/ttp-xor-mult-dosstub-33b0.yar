rule TTP_XOR_MULT_DOSStub_33b0 {
  strings:
    $key_33b0 = { 67 d8 [2] 13 c0 [2] 54 c2 [2] 13 d3 [2] 5d df [2] 51 d5 [2] 46 de [2] 5d 90 [2] 60 }

  condition:
    any of them
}