rule TTP_XOR_MULT_DOSStub_93bc {
  strings:
    $key_93bc = { c7 d4 [2] b3 cc [2] f4 ce [2] b3 df [2] fd d3 [2] f1 d9 [2] e6 d2 [2] fd 9c [2] c0 }

  condition:
    any of them
}