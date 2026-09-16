rule TTP_XOR_MULT_DOSStub_28bf {
  strings:
    $key_28bf = { 7c d7 [2] 08 cf [2] 4f cd [2] 08 dc [2] 46 d0 [2] 4a da [2] 5d d1 [2] 46 9f [2] 7b }

  condition:
    any of them
}