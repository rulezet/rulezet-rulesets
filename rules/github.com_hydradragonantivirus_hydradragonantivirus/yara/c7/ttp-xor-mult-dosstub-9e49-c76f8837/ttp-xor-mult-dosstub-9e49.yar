rule TTP_XOR_MULT_DOSStub_9e49 {
  strings:
    $key_9e49 = { ca 21 [2] be 39 [2] f9 3b [2] be 2a [2] f0 26 [2] fc 2c [2] eb 27 [2] f0 69 [2] cd }

  condition:
    any of them
}