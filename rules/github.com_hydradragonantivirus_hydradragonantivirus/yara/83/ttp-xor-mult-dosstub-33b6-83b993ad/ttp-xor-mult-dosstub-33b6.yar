rule TTP_XOR_MULT_DOSStub_33b6 {
  strings:
    $key_33b6 = { 67 de [2] 13 c6 [2] 54 c4 [2] 13 d5 [2] 5d d9 [2] 51 d3 [2] 46 d8 [2] 5d 96 [2] 60 }

  condition:
    any of them
}