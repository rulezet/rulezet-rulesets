rule TTP_XOR_MULT_DOSStub_85aa {
  strings:
    $key_85aa = { d1 c2 [2] a5 da [2] e2 d8 [2] a5 c9 [2] eb c5 [2] e7 cf [2] f0 c4 [2] eb 8a [2] d6 }

  condition:
    any of them
}