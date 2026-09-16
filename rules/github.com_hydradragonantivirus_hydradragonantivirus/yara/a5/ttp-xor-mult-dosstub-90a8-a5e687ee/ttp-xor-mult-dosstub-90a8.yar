rule TTP_XOR_MULT_DOSStub_90a8 {
  strings:
    $key_90a8 = { c4 c0 [2] b0 d8 [2] f7 da [2] b0 cb [2] fe c7 [2] f2 cd [2] e5 c6 [2] fe 88 [2] c3 }

  condition:
    any of them
}