rule TTP_XOR_MULT_DOSStub_90b4 {
  strings:
    $key_90b4 = { c4 dc [2] b0 c4 [2] f7 c6 [2] b0 d7 [2] fe db [2] f2 d1 [2] e5 da [2] fe 94 [2] c3 }

  condition:
    any of them
}