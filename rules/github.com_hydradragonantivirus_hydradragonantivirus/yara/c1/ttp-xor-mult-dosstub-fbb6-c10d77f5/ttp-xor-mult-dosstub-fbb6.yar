rule TTP_XOR_MULT_DOSStub_fbb6 {
  strings:
    $key_fbb6 = { af de [2] db c6 [2] 9c c4 [2] db d5 [2] 95 d9 [2] 99 d3 [2] 8e d8 [2] 95 96 [2] a8 }

  condition:
    any of them
}