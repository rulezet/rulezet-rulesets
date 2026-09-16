rule TTP_XOR_MULT_DOSStub_40bc {
  strings:
    $key_40bc = { 14 d4 [2] 60 cc [2] 27 ce [2] 60 df [2] 2e d3 [2] 22 d9 [2] 35 d2 [2] 2e 9c [2] 13 }

  condition:
    any of them
}