rule TTP_XOR_MULT_DOSStub_41bc {
  strings:
    $key_41bc = { 15 d4 [2] 61 cc [2] 26 ce [2] 61 df [2] 2f d3 [2] 23 d9 [2] 34 d2 [2] 2f 9c [2] 12 }

  condition:
    any of them
}