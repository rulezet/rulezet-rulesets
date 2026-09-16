rule TTP_XOR_MULT_DOSStub_9e6d {
  strings:
    $key_9e6d = { ca 05 [2] be 1d [2] f9 1f [2] be 0e [2] f0 02 [2] fc 08 [2] eb 03 [2] f0 4d [2] cd }

  condition:
    any of them
}