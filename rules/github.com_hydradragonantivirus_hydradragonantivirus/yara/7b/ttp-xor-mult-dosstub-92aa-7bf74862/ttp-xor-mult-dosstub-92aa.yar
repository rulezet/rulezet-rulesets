rule TTP_XOR_MULT_DOSStub_92aa {
  strings:
    $key_92aa = { c6 c2 [2] b2 da [2] f5 d8 [2] b2 c9 [2] fc c5 [2] f0 cf [2] e7 c4 [2] fc 8a [2] c1 }

  condition:
    any of them
}