rule TTP_XOR_MULT_DOSStub_85bc {
  strings:
    $key_85bc = { d1 d4 [2] a5 cc [2] e2 ce [2] a5 df [2] eb d3 [2] e7 d9 [2] f0 d2 [2] eb 9c [2] d6 }

  condition:
    any of them
}