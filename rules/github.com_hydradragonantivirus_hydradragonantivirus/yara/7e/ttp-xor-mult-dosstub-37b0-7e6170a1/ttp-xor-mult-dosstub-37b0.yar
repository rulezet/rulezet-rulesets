rule TTP_XOR_MULT_DOSStub_37b0 {
  strings:
    $key_37b0 = { 63 d8 [2] 17 c0 [2] 50 c2 [2] 17 d3 [2] 59 df [2] 55 d5 [2] 42 de [2] 59 90 [2] 64 }

  condition:
    any of them
}