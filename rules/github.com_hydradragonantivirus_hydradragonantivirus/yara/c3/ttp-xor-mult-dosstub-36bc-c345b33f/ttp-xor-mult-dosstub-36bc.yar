rule TTP_XOR_MULT_DOSStub_36bc {
  strings:
    $key_36bc = { 62 d4 [2] 16 cc [2] 51 ce [2] 16 df [2] 58 d3 [2] 54 d9 [2] 43 d2 [2] 58 9c [2] 65 }

  condition:
    any of them
}