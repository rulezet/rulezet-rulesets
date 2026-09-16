rule TTP_XOR_MULT_DOSStub_48bf {
  strings:
    $key_48bf = { 1c d7 [2] 68 cf [2] 2f cd [2] 68 dc [2] 26 d0 [2] 2a da [2] 3d d1 [2] 26 9f [2] 1b }

  condition:
    any of them
}