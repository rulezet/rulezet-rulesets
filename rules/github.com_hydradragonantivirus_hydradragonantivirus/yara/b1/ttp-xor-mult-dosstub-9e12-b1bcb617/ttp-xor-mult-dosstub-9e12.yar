rule TTP_XOR_MULT_DOSStub_9e12 {
  strings:
    $key_9e12 = { ca 7a [2] be 62 [2] f9 60 [2] be 71 [2] f0 7d [2] fc 77 [2] eb 7c [2] f0 32 [2] cd }

  condition:
    any of them
}