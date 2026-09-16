rule TTP_XOR_MULT_DOSStub_9e40 {
  strings:
    $key_9e40 = { ca 28 [2] be 30 [2] f9 32 [2] be 23 [2] f0 2f [2] fc 25 [2] eb 2e [2] f0 60 [2] cd }

  condition:
    any of them
}