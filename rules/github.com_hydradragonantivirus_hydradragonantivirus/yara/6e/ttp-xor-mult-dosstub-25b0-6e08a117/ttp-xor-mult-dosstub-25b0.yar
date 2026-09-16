rule TTP_XOR_MULT_DOSStub_25b0 {
  strings:
    $key_25b0 = { 71 d8 [2] 05 c0 [2] 42 c2 [2] 05 d3 [2] 4b df [2] 47 d5 [2] 50 de [2] 4b 90 [2] 76 }

  condition:
    any of them
}