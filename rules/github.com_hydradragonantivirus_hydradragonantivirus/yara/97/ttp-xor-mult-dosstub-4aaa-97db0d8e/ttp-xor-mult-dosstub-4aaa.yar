rule TTP_XOR_MULT_DOSStub_4aaa {
  strings:
    $key_4aaa = { 1e c2 [2] 6a da [2] 2d d8 [2] 6a c9 [2] 24 c5 [2] 28 cf [2] 3f c4 [2] 24 8a [2] 19 }

  condition:
    any of them
}