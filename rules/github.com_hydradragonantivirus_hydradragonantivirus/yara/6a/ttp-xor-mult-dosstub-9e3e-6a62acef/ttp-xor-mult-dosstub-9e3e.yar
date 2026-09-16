rule TTP_XOR_MULT_DOSStub_9e3e {
  strings:
    $key_9e3e = { ca 56 [2] be 4e [2] f9 4c [2] be 5d [2] f0 51 [2] fc 5b [2] eb 50 [2] f0 1e [2] cd }

  condition:
    any of them
}