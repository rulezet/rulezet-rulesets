rule TTP_XOR_MULT_DOSStub_51bc {
  strings:
    $key_51bc = { 05 d4 [2] 71 cc [2] 36 ce [2] 71 df [2] 3f d3 [2] 33 d9 [2] 24 d2 [2] 3f 9c [2] 02 }

  condition:
    any of them
}