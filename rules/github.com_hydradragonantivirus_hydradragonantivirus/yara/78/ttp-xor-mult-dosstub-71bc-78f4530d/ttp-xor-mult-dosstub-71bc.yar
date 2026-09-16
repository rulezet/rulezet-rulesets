rule TTP_XOR_MULT_DOSStub_71bc {
  strings:
    $key_71bc = { 25 d4 [2] 51 cc [2] 16 ce [2] 51 df [2] 1f d3 [2] 13 d9 [2] 04 d2 [2] 1f 9c [2] 22 }

  condition:
    any of them
}