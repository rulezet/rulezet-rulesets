rule TTP_XOR_MULT_DOSStub_37bc {
  strings:
    $key_37bc = { 63 d4 [2] 17 cc [2] 50 ce [2] 17 df [2] 59 d3 [2] 55 d9 [2] 42 d2 [2] 59 9c [2] 64 }

  condition:
    any of them
}