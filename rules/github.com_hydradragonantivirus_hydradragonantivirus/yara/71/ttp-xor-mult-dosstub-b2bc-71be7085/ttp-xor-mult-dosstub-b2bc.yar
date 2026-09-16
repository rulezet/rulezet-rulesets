rule TTP_XOR_MULT_DOSStub_b2bc {
  strings:
    $key_b2bc = { e6 d4 [2] 92 cc [2] d5 ce [2] 92 df [2] dc d3 [2] d0 d9 [2] c7 d2 [2] dc 9c [2] e1 }

  condition:
    any of them
}