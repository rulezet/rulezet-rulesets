rule TTP_XOR_MULT_DOSStub_9e5d {
  strings:
    $key_9e5d = { ca 35 [2] be 2d [2] f9 2f [2] be 3e [2] f0 32 [2] fc 38 [2] eb 33 [2] f0 7d [2] cd }

  condition:
    any of them
}