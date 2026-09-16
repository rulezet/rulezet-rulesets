rule TTP_XOR_MULT_DOSStub_06b0 {
  strings:
    $key_06b0 = { 52 d8 [2] 26 c0 [2] 61 c2 [2] 26 d3 [2] 68 df [2] 64 d5 [2] 73 de [2] 68 90 [2] 55 }

  condition:
    any of them
}