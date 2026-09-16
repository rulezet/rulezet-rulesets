rule TTP_XOR_MULT_DOSStub_70bc {
  strings:
    $key_70bc = { 24 d4 [2] 50 cc [2] 17 ce [2] 50 df [2] 1e d3 [2] 12 d9 [2] 05 d2 [2] 1e 9c [2] 23 }

  condition:
    any of them
}