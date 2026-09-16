rule TTP_XOR_MULT_DOSStub_52bc {
  strings:
    $key_52bc = { 06 d4 [2] 72 cc [2] 35 ce [2] 72 df [2] 3c d3 [2] 30 d9 [2] 27 d2 [2] 3c 9c [2] 01 }

  condition:
    any of them
}