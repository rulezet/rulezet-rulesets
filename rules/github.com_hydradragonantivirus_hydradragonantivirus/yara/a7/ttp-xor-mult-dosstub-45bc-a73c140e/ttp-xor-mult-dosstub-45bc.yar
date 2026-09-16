rule TTP_XOR_MULT_DOSStub_45bc {
  strings:
    $key_45bc = { 11 d4 [2] 65 cc [2] 22 ce [2] 65 df [2] 2b d3 [2] 27 d9 [2] 30 d2 [2] 2b 9c [2] 16 }

  condition:
    any of them
}