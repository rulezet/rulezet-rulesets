rule TTP_XOR_MULT_DOSStub_3abc {
  strings:
    $key_3abc = { 6e d4 [2] 1a cc [2] 5d ce [2] 1a df [2] 54 d3 [2] 58 d9 [2] 4f d2 [2] 54 9c [2] 69 }

  condition:
    any of them
}