rule TTP_XOR_MULT_DOSStub_9e90 {
  strings:
    $key_9e90 = { ca f8 [2] be e0 [2] f9 e2 [2] be f3 [2] f0 ff [2] fc f5 [2] eb fe [2] f0 b0 [2] cd }

  condition:
    any of them
}