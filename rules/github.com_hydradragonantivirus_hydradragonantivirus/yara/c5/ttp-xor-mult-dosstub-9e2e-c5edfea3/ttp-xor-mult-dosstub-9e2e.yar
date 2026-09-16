rule TTP_XOR_MULT_DOSStub_9e2e {
  strings:
    $key_9e2e = { ca 46 [2] be 5e [2] f9 5c [2] be 4d [2] f0 41 [2] fc 4b [2] eb 40 [2] f0 0e [2] cd }

  condition:
    any of them
}