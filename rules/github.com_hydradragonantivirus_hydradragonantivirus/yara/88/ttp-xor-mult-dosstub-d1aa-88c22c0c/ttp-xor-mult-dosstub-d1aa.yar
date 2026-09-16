rule TTP_XOR_MULT_DOSStub_d1aa {
  strings:
    $key_d1aa = { 85 c2 [2] f1 da [2] b6 d8 [2] f1 c9 [2] bf c5 [2] b3 cf [2] a4 c4 [2] bf 8a [2] 82 }

  condition:
    any of them
}