rule TTP_XOR_MULT_DOSStub_78bc {
  strings:
    $key_78bc = { 2c d4 [2] 58 cc [2] 1f ce [2] 58 df [2] 16 d3 [2] 1a d9 [2] 0d d2 [2] 16 9c [2] 2b }

  condition:
    any of them
}