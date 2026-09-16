rule TTP_XOR_MULT_DOSStub_84bc {
  strings:
    $key_84bc = { d0 d4 [2] a4 cc [2] e3 ce [2] a4 df [2] ea d3 [2] e6 d9 [2] f1 d2 [2] ea 9c [2] d7 }

  condition:
    any of them
}