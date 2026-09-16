rule TTP_XOR_MULT_DOSStub_cbb6 {
  strings:
    $key_cbb6 = { 9f de [2] eb c6 [2] ac c4 [2] eb d5 [2] a5 d9 [2] a9 d3 [2] be d8 [2] a5 96 [2] 98 }

  condition:
    any of them
}