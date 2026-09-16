rule TTP_XOR_MULT_DOSStub_9ea0 {
  strings:
    $key_9ea0 = { ca c8 [2] be d0 [2] f9 d2 [2] be c3 [2] f0 cf [2] fc c5 [2] eb ce [2] f0 80 [2] cd }

  condition:
    any of them
}