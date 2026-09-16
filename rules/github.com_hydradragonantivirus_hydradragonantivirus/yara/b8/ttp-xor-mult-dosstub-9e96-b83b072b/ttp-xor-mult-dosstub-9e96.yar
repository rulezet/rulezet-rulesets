rule TTP_XOR_MULT_DOSStub_9e96 {
  strings:
    $key_9e96 = { ca fe [2] be e6 [2] f9 e4 [2] be f5 [2] f0 f9 [2] fc f3 [2] eb f8 [2] f0 b6 [2] cd }

  condition:
    any of them
}