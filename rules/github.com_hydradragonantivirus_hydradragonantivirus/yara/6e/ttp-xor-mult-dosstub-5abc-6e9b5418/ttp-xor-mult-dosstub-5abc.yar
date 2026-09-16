rule TTP_XOR_MULT_DOSStub_5abc {
  strings:
    $key_5abc = { 0e d4 [2] 7a cc [2] 3d ce [2] 7a df [2] 34 d3 [2] 38 d9 [2] 2f d2 [2] 34 9c [2] 09 }

  condition:
    any of them
}