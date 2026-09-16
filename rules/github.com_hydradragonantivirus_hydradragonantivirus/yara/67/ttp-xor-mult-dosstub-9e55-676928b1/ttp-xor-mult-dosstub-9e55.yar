rule TTP_XOR_MULT_DOSStub_9e55 {
  strings:
    $key_9e55 = { ca 3d [2] be 25 [2] f9 27 [2] be 36 [2] f0 3a [2] fc 30 [2] eb 3b [2] f0 75 [2] cd }

  condition:
    any of them
}