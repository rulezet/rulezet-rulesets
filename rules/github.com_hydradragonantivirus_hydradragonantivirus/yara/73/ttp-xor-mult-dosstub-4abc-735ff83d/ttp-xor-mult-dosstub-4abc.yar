rule TTP_XOR_MULT_DOSStub_4abc {
  strings:
    $key_4abc = { 1e d4 [2] 6a cc [2] 2d ce [2] 6a df [2] 24 d3 [2] 28 d9 [2] 3f d2 [2] 24 9c [2] 19 }

  condition:
    any of them
}