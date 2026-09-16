rule TTP_XOR_MULT_DOSStub_9e0e {
  strings:
    $key_9e0e = { ca 66 [2] be 7e [2] f9 7c [2] be 6d [2] f0 61 [2] fc 6b [2] eb 60 [2] f0 2e [2] cd }

  condition:
    any of them
}