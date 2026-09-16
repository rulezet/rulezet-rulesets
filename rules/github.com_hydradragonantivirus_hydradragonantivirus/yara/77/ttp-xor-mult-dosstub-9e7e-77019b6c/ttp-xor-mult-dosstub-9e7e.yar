rule TTP_XOR_MULT_DOSStub_9e7e {
  strings:
    $key_9e7e = { ca 16 [2] be 0e [2] f9 0c [2] be 1d [2] f0 11 [2] fc 1b [2] eb 10 [2] f0 5e [2] cd }

  condition:
    any of them
}