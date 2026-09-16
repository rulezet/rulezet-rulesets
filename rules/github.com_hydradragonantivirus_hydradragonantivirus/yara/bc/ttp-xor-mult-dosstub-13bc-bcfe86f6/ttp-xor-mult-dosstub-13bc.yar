rule TTP_XOR_MULT_DOSStub_13bc {
  strings:
    $key_13bc = { 47 d4 [2] 33 cc [2] 74 ce [2] 33 df [2] 7d d3 [2] 71 d9 [2] 66 d2 [2] 7d 9c [2] 40 }

  condition:
    any of them
}