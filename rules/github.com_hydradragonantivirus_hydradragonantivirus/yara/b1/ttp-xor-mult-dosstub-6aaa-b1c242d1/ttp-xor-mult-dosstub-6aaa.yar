rule TTP_XOR_MULT_DOSStub_6aaa {
  strings:
    $key_6aaa = { 3e c2 [2] 4a da [2] 0d d8 [2] 4a c9 [2] 04 c5 [2] 08 cf [2] 1f c4 [2] 04 8a [2] 39 }

  condition:
    any of them
}