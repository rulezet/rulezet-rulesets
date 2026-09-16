rule TTP_XOR_MULT_DOSStub_9ed2 {
  strings:
    $key_9ed2 = { ca ba [2] be a2 [2] f9 a0 [2] be b1 [2] f0 bd [2] fc b7 [2] eb bc [2] f0 f2 [2] cd }

  condition:
    any of them
}