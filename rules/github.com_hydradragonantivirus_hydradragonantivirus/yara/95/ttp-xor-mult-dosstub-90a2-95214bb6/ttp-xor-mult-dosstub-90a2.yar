rule TTP_XOR_MULT_DOSStub_90a2 {
  strings:
    $key_90a2 = { c4 ca [2] b0 d2 [2] f7 d0 [2] b0 c1 [2] fe cd [2] f2 c7 [2] e5 cc [2] fe 82 [2] c3 }

  condition:
    any of them
}