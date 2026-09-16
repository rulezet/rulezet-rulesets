rule TTP_XOR_MULT_DOSStub_9e57 {
  strings:
    $key_9e57 = { ca 3f [2] be 27 [2] f9 25 [2] be 34 [2] f0 38 [2] fc 32 [2] eb 39 [2] f0 77 [2] cd }

  condition:
    any of them
}