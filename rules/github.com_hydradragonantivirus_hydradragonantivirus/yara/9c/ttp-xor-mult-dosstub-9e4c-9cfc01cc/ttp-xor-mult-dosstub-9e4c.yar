rule TTP_XOR_MULT_DOSStub_9e4c {
  strings:
    $key_9e4c = { ca 24 [2] be 3c [2] f9 3e [2] be 2f [2] f0 23 [2] fc 29 [2] eb 22 [2] f0 6c [2] cd }

  condition:
    any of them
}