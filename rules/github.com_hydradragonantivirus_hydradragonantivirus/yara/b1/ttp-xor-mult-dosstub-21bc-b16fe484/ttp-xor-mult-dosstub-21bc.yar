rule TTP_XOR_MULT_DOSStub_21bc {
  strings:
    $key_21bc = { 75 d4 [2] 01 cc [2] 46 ce [2] 01 df [2] 4f d3 [2] 43 d9 [2] 54 d2 [2] 4f 9c [2] 72 }

  condition:
    any of them
}