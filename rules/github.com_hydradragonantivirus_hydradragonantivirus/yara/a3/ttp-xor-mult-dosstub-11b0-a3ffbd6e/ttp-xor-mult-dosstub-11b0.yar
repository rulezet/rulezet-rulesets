rule TTP_XOR_MULT_DOSStub_11b0 {
  strings:
    $key_11b0 = { 45 d8 [2] 31 c0 [2] 76 c2 [2] 31 d3 [2] 7f df [2] 73 d5 [2] 64 de [2] 7f 90 [2] 42 }

  condition:
    any of them
}