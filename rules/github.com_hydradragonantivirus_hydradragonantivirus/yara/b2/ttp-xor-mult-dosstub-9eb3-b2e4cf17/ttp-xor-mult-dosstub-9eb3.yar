rule TTP_XOR_MULT_DOSStub_9eb3 {
  strings:
    $key_9eb3 = { ca db [2] be c3 [2] f9 c1 [2] be d0 [2] f0 dc [2] fc d6 [2] eb dd [2] f0 93 [2] cd }

  condition:
    any of them
}