rule TTP_XOR_MULT_DOSStub_31bc {
  strings:
    $key_31bc = { 65 d4 [2] 11 cc [2] 56 ce [2] 11 df [2] 5f d3 [2] 53 d9 [2] 44 d2 [2] 5f 9c [2] 62 }

  condition:
    any of them
}