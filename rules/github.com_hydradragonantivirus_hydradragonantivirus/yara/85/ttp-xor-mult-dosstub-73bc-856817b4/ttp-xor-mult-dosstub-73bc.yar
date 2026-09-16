rule TTP_XOR_MULT_DOSStub_73bc {
  strings:
    $key_73bc = { 27 d4 [2] 53 cc [2] 14 ce [2] 53 df [2] 1d d3 [2] 11 d9 [2] 06 d2 [2] 1d 9c [2] 20 }

  condition:
    any of them
}