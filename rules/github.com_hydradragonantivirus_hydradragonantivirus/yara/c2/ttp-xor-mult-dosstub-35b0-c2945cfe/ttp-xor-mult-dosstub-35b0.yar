rule TTP_XOR_MULT_DOSStub_35b0 {
  strings:
    $key_35b0 = { 61 d8 [2] 15 c0 [2] 52 c2 [2] 15 d3 [2] 5b df [2] 57 d5 [2] 40 de [2] 5b 90 [2] 66 }

  condition:
    any of them
}