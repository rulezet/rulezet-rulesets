rule TTP_XOR_MULT_DOSStub_9ef6 {
  strings:
    $key_9ef6 = { ca 9e [2] be 86 [2] f9 84 [2] be 95 [2] f0 99 [2] fc 93 [2] eb 98 [2] f0 d6 [2] cd }

  condition:
    any of them
}