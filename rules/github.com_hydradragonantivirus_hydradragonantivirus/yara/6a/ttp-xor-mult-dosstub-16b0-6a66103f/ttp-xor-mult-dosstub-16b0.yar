rule TTP_XOR_MULT_DOSStub_16b0 {
  strings:
    $key_16b0 = { 42 d8 [2] 36 c0 [2] 71 c2 [2] 36 d3 [2] 78 df [2] 74 d5 [2] 63 de [2] 78 90 [2] 45 }

  condition:
    any of them
}