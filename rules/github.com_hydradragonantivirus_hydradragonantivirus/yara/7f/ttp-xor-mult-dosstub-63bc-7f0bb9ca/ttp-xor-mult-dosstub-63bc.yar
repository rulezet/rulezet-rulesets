rule TTP_XOR_MULT_DOSStub_63bc {
  strings:
    $key_63bc = { 37 d4 [2] 43 cc [2] 04 ce [2] 43 df [2] 0d d3 [2] 01 d9 [2] 16 d2 [2] 0d 9c [2] 30 }

  condition:
    any of them
}