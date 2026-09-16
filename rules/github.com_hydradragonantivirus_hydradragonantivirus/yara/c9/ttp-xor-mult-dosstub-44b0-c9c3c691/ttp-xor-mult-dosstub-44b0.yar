rule TTP_XOR_MULT_DOSStub_44b0 {
  strings:
    $key_44b0 = { 10 d8 [2] 64 c0 [2] 23 c2 [2] 64 d3 [2] 2a df [2] 26 d5 [2] 31 de [2] 2a 90 [2] 17 }

  condition:
    any of them
}