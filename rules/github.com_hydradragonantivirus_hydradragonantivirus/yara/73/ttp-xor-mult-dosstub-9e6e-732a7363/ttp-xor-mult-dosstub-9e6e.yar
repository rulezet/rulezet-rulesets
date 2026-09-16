rule TTP_XOR_MULT_DOSStub_9e6e {
  strings:
    $key_9e6e = { ca 06 [2] be 1e [2] f9 1c [2] be 0d [2] f0 01 [2] fc 0b [2] eb 00 [2] f0 4e [2] cd }

  condition:
    any of them
}