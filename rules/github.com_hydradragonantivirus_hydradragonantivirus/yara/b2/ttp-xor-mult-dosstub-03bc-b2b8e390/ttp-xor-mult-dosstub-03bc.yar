rule TTP_XOR_MULT_DOSStub_03bc {
  strings:
    $key_03bc = { 57 d4 [2] 23 cc [2] 64 ce [2] 23 df [2] 6d d3 [2] 61 d9 [2] 76 d2 [2] 6d 9c [2] 50 }

  condition:
    any of them
}