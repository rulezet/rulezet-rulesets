rule TTP_XOR_MULT_DOSStub_59bc {
  strings:
    $key_59bc = { 0d d4 [2] 79 cc [2] 3e ce [2] 79 df [2] 37 d3 [2] 3b d9 [2] 2c d2 [2] 37 9c [2] 0a }

  condition:
    any of them
}