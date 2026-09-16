rule TTP_XOR_MULT_DOSStub_2aaa {
  strings:
    $key_2aaa = { 7e c2 [2] 0a da [2] 4d d8 [2] 0a c9 [2] 44 c5 [2] 48 cf [2] 5f c4 [2] 44 8a [2] 79 }

  condition:
    any of them
}