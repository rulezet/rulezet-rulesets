rule TTP_XOR_MULT_DOSStub_46bc {
  strings:
    $key_46bc = { 12 d4 [2] 66 cc [2] 21 ce [2] 66 df [2] 28 d3 [2] 24 d9 [2] 33 d2 [2] 28 9c [2] 15 }

  condition:
    any of them
}