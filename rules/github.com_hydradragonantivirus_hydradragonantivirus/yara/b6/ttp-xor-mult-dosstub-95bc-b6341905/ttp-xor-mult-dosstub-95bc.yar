rule TTP_XOR_MULT_DOSStub_95bc {
  strings:
    $key_95bc = { c1 d4 [2] b5 cc [2] f2 ce [2] b5 df [2] fb d3 [2] f7 d9 [2] e0 d2 [2] fb 9c [2] c6 }

  condition:
    any of them
}