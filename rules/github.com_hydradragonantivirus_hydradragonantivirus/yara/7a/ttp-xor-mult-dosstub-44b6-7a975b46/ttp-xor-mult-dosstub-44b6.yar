rule TTP_XOR_MULT_DOSStub_44b6 {
  strings:
    $key_44b6 = { 10 de [2] 64 c6 [2] 23 c4 [2] 64 d5 [2] 2a d9 [2] 26 d3 [2] 31 d8 [2] 2a 96 [2] 17 }

  condition:
    any of them
}