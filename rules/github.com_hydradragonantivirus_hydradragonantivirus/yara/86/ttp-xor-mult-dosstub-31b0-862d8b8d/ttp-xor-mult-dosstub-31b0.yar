rule TTP_XOR_MULT_DOSStub_31b0 {
  strings:
    $key_31b0 = { 65 d8 [2] 11 c0 [2] 56 c2 [2] 11 d3 [2] 5f df [2] 53 d5 [2] 44 de [2] 5f 90 [2] 62 }

  condition:
    any of them
}