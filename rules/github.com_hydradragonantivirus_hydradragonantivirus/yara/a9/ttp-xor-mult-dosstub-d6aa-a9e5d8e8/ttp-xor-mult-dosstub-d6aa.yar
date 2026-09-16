rule TTP_XOR_MULT_DOSStub_d6aa {
  strings:
    $key_d6aa = { 82 c2 [2] f6 da [2] b1 d8 [2] f6 c9 [2] b8 c5 [2] b4 cf [2] a3 c4 [2] b8 8a [2] 85 }

  condition:
    any of them
}