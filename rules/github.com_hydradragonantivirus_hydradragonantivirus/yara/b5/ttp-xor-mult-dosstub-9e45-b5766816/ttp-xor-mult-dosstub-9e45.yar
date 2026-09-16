rule TTP_XOR_MULT_DOSStub_9e45 {
  strings:
    $key_9e45 = { ca 2d [2] be 35 [2] f9 37 [2] be 26 [2] f0 2a [2] fc 20 [2] eb 2b [2] f0 65 [2] cd }

  condition:
    any of them
}