rule TTP_XOR_MULT_DOSStub_9e2d {
  strings:
    $key_9e2d = { ca 45 [2] be 5d [2] f9 5f [2] be 4e [2] f0 42 [2] fc 48 [2] eb 43 [2] f0 0d [2] cd }

  condition:
    any of them
}