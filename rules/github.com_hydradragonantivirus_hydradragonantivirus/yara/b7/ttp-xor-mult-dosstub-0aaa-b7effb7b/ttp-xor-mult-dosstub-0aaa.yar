rule TTP_XOR_MULT_DOSStub_0aaa {
  strings:
    $key_0aaa = { 5e c2 [2] 2a da [2] 6d d8 [2] 2a c9 [2] 64 c5 [2] 68 cf [2] 7f c4 [2] 64 8a [2] 59 }

  condition:
    any of them
}