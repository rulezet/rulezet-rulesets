rule TTP_XOR_MULT_DOSStub_68bf {
  strings:
    $key_68bf = { 3c d7 [2] 48 cf [2] 0f cd [2] 48 dc [2] 06 d0 [2] 0a da [2] 1d d1 [2] 06 9f [2] 3b }

  condition:
    any of them
}