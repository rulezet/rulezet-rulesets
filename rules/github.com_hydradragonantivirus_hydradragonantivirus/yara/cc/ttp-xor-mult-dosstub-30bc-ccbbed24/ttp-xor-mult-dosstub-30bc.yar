rule TTP_XOR_MULT_DOSStub_30bc {
  strings:
    $key_30bc = { 64 d4 [2] 10 cc [2] 57 ce [2] 10 df [2] 5e d3 [2] 52 d9 [2] 45 d2 [2] 5e 9c [2] 63 }

  condition:
    any of them
}