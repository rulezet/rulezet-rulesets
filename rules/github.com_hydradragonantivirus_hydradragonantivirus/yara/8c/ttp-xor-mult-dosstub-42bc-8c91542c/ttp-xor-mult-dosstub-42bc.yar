rule TTP_XOR_MULT_DOSStub_42bc {
  strings:
    $key_42bc = { 16 d4 [2] 62 cc [2] 25 ce [2] 62 df [2] 2c d3 [2] 20 d9 [2] 37 d2 [2] 2c 9c [2] 11 }

  condition:
    any of them
}