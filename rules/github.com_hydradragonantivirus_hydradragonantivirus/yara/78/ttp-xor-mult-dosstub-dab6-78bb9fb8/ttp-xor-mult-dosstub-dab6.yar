rule TTP_XOR_MULT_DOSStub_dab6 {
  strings:
    $key_dab6 = { 8e de [2] fa c6 [2] bd c4 [2] fa d5 [2] b4 d9 [2] b8 d3 [2] af d8 [2] b4 96 [2] 89 }

  condition:
    any of them
}