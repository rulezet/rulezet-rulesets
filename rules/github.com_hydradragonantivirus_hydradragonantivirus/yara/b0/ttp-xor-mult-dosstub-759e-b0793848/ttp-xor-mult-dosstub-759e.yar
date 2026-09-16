rule TTP_XOR_MULT_DOSStub_759e {
  strings:
    $key_759e = { 21 f6 [2] 55 ee [2] 12 ec [2] 55 fd [2] 1b f1 [2] 17 fb [2] 00 f0 [2] 1b be [2] 26 }

  condition:
    any of them
}