rule TTP_XOR_MULT_DOSStub_60bc {
  strings:
    $key_60bc = { 34 d4 [2] 40 cc [2] 07 ce [2] 40 df [2] 0e d3 [2] 02 d9 [2] 15 d2 [2] 0e 9c [2] 33 }

  condition:
    any of them
}