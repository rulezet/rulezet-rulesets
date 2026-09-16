rule TTP_XOR_MULT_DOSStub_17bc {
  strings:
    $key_17bc = { 43 d4 [2] 37 cc [2] 70 ce [2] 37 df [2] 79 d3 [2] 75 d9 [2] 62 d2 [2] 79 9c [2] 44 }

  condition:
    any of them
}