rule TTP_XOR_MULT_DOSStub_22bc {
  strings:
    $key_22bc = { 76 d4 [2] 02 cc [2] 45 ce [2] 02 df [2] 4c d3 [2] 40 d9 [2] 57 d2 [2] 4c 9c [2] 71 }

  condition:
    any of them
}