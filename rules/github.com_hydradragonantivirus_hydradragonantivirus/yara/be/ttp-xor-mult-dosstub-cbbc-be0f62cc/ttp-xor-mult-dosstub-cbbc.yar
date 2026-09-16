rule TTP_XOR_MULT_DOSStub_cbbc {
  strings:
    $key_cbbc = { 9f d4 [2] eb cc [2] ac ce [2] eb df [2] a5 d3 [2] a9 d9 [2] be d2 [2] a5 9c [2] 98 }

  condition:
    any of them
}