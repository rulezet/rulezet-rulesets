rule TTP_XOR_MULT_DOSStub_78bf {
  strings:
    $key_78bf = { 2c d7 [2] 58 cf [2] 1f cd [2] 58 dc [2] 16 d0 [2] 1a da [2] 0d d1 [2] 16 9f [2] 2b }

  condition:
    any of them
}