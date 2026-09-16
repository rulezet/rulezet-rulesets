rule TTP_XOR_MULT_DOSStub_14bc {
  strings:
    $key_14bc = { 40 d4 [2] 34 cc [2] 73 ce [2] 34 df [2] 7a d3 [2] 76 d9 [2] 61 d2 [2] 7a 9c [2] 47 }

  condition:
    any of them
}