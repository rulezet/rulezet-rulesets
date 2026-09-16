rule TTP_XOR_MULT_DOSStub_9ee1 {
  strings:
    $key_9ee1 = { ca 89 [2] be 91 [2] f9 93 [2] be 82 [2] f0 8e [2] fc 84 [2] eb 8f [2] f0 c1 [2] cd }

  condition:
    any of them
}