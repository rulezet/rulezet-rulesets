rule TTP_XOR_MULT_DOSStub_96bc {
  strings:
    $key_96bc = { c2 d4 [2] b6 cc [2] f1 ce [2] b6 df [2] f8 d3 [2] f4 d9 [2] e3 d2 [2] f8 9c [2] c5 }

  condition:
    any of them
}