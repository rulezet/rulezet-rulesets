rule TTP_XOR_MULT_DOSStub_9e82 {
  strings:
    $key_9e82 = { ca ea [2] be f2 [2] f9 f0 [2] be e1 [2] f0 ed [2] fc e7 [2] eb ec [2] f0 a2 [2] cd }

  condition:
    any of them
}