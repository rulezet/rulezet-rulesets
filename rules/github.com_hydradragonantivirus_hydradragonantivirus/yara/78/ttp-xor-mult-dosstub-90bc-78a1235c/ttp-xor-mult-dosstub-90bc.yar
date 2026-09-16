rule TTP_XOR_MULT_DOSStub_90bc {
  strings:
    $key_90bc = { c4 d4 [2] b0 cc [2] f7 ce [2] b0 df [2] fe d3 [2] f2 d9 [2] e5 d2 [2] fe 9c [2] c3 }

  condition:
    any of them
}