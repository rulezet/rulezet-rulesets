rule TTP_XOR_MULT_DOSStub_e1bc {
  strings:
    $key_e1bc = { b5 d4 [2] c1 cc [2] 86 ce [2] c1 df [2] 8f d3 [2] 83 d9 [2] 94 d2 [2] 8f 9c [2] b2 }

  condition:
    any of them
}