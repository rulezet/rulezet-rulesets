rule TTP_XOR_MULT_DOSStub_cbb0 {
  strings:
    $key_cbb0 = { 9f d8 [2] eb c0 [2] ac c2 [2] eb d3 [2] a5 df [2] a9 d5 [2] be de [2] a5 90 [2] 98 }

  condition:
    any of them
}