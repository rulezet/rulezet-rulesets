rule TTP_XOR_MULT_DOSStub_50b0 {
  strings:
    $key_50b0 = { 04 d8 [2] 70 c0 [2] 37 c2 [2] 70 d3 [2] 3e df [2] 32 d5 [2] 25 de [2] 3e 90 [2] 03 }

  condition:
    any of them
}