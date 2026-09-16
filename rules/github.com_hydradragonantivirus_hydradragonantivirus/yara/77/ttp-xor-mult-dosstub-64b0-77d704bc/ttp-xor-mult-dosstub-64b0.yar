rule TTP_XOR_MULT_DOSStub_64b0 {
  strings:
    $key_64b0 = { 30 d8 [2] 44 c0 [2] 03 c2 [2] 44 d3 [2] 0a df [2] 06 d5 [2] 11 de [2] 0a 90 [2] 37 }

  condition:
    any of them
}