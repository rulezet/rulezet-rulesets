rule TTP_XOR_MULT_DOSStub_e4bc {
  strings:
    $key_e4bc = { b0 d4 [2] c4 cc [2] 83 ce [2] c4 df [2] 8a d3 [2] 86 d9 [2] 91 d2 [2] 8a 9c [2] b7 }

  condition:
    any of them
}