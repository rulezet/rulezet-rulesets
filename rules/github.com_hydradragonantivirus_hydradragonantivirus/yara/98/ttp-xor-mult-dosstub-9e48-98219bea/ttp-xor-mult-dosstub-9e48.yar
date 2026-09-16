rule TTP_XOR_MULT_DOSStub_9e48 {
  strings:
    $key_9e48 = { ca 20 [2] be 38 [2] f9 3a [2] be 2b [2] f0 27 [2] fc 2d [2] eb 26 [2] f0 68 [2] cd }

  condition:
    any of them
}