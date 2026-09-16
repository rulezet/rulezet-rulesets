rule TTP_XOR_MULT_DOSStub_0abc {
  strings:
    $key_0abc = { 5e d4 [2] 2a cc [2] 6d ce [2] 2a df [2] 64 d3 [2] 68 d9 [2] 7f d2 [2] 64 9c [2] 59 }

  condition:
    any of them
}