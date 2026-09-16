rule TTP_XOR_MULT_DOSStub_18bf {
  strings:
    $key_18bf = { 4c d7 [2] 38 cf [2] 7f cd [2] 38 dc [2] 76 d0 [2] 7a da [2] 6d d1 [2] 76 9f [2] 4b }

  condition:
    any of them
}