rule TTP_XOR_MULT_DOSStub_90a9 {
  strings:
    $key_90a9 = { c4 c1 [2] b0 d9 [2] f7 db [2] b0 ca [2] fe c6 [2] f2 cc [2] e5 c7 [2] fe 89 [2] c3 }

  condition:
    any of them
}