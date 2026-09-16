rule TTP_XOR_MULT_DOSStub_9eb2 {
  strings:
    $key_9eb2 = { ca da [2] be c2 [2] f9 c0 [2] be d1 [2] f0 dd [2] fc d7 [2] eb dc [2] f0 92 [2] cd }

  condition:
    any of them
}