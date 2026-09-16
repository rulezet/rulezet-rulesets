rule TTP_XOR_MULT_DOSStub_57b0 {
  strings:
    $key_57b0 = { 03 d8 [2] 77 c0 [2] 30 c2 [2] 77 d3 [2] 39 df [2] 35 d5 [2] 22 de [2] 39 90 [2] 04 }

  condition:
    any of them
}