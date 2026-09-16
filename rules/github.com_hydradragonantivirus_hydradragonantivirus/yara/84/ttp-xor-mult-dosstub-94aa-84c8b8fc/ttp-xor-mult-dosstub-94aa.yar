rule TTP_XOR_MULT_DOSStub_94aa {
  strings:
    $key_94aa = { c0 c2 [2] b4 da [2] f3 d8 [2] b4 c9 [2] fa c5 [2] f6 cf [2] e1 c4 [2] fa 8a [2] c7 }

  condition:
    any of them
}