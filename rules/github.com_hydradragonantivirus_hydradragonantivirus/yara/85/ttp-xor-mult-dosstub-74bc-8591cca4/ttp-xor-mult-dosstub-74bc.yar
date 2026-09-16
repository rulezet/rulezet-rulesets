rule TTP_XOR_MULT_DOSStub_74bc {
  strings:
    $key_74bc = { 20 d4 [2] 54 cc [2] 13 ce [2] 54 df [2] 1a d3 [2] 16 d9 [2] 01 d2 [2] 1a 9c [2] 27 }

  condition:
    any of them
}