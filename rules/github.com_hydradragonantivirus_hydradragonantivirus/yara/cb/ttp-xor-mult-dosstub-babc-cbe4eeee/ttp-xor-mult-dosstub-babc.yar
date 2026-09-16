rule TTP_XOR_MULT_DOSStub_babc {
  strings:
    $key_babc = { ee d4 [2] 9a cc [2] dd ce [2] 9a df [2] d4 d3 [2] d8 d9 [2] cf d2 [2] d4 9c [2] e9 }

  condition:
    any of them
}