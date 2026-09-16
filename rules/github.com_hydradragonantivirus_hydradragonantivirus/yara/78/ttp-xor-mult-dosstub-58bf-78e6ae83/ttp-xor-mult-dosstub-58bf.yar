rule TTP_XOR_MULT_DOSStub_58bf {
  strings:
    $key_58bf = { 0c d7 [2] 78 cf [2] 3f cd [2] 78 dc [2] 36 d0 [2] 3a da [2] 2d d1 [2] 36 9f [2] 0b }

  condition:
    any of them
}