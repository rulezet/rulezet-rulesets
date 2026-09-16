rule TTP_XOR_MULT_DOSStub_9e86 {
  strings:
    $key_9e86 = { ca ee [2] be f6 [2] f9 f4 [2] be e5 [2] f0 e9 [2] fc e3 [2] eb e8 [2] f0 a6 [2] cd }

  condition:
    any of them
}