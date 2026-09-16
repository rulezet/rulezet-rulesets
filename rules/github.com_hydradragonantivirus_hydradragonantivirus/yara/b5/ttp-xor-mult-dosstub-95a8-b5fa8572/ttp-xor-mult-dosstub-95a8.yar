rule TTP_XOR_MULT_DOSStub_95a8 {
  strings:
    $key_95a8 = { c1 c0 [2] b5 d8 [2] f2 da [2] b5 cb [2] fb c7 [2] f7 cd [2] e0 c6 [2] fb 88 [2] c6 }

  condition:
    any of them
}