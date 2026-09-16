rule TTP_XOR_MULT_DOSStub_9eaa {
  strings:
    $key_9eaa = { ca c2 [2] be da [2] f9 d8 [2] be c9 [2] f0 c5 [2] fc cf [2] eb c4 [2] f0 8a [2] cd }

  condition:
    any of them
}