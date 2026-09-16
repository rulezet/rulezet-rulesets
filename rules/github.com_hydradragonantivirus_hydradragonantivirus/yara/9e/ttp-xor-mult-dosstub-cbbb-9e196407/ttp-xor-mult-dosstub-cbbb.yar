rule TTP_XOR_MULT_DOSStub_cbbb {
  strings:
    $key_cbbb = { 9f d3 [2] eb cb [2] ac c9 [2] eb d8 [2] a5 d4 [2] a9 de [2] be d5 [2] a5 9b [2] 98 }

  condition:
    any of them
}