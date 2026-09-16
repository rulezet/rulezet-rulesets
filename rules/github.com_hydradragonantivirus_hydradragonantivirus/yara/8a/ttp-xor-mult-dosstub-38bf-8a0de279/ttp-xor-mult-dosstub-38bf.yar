rule TTP_XOR_MULT_DOSStub_38bf {
  strings:
    $key_38bf = { 6c d7 [2] 18 cf [2] 5f cd [2] 18 dc [2] 56 d0 [2] 5a da [2] 4d d1 [2] 56 9f [2] 6b }

  condition:
    any of them
}