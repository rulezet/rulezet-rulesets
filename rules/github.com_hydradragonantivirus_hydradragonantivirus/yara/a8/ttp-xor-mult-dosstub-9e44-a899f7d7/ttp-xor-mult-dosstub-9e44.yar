rule TTP_XOR_MULT_DOSStub_9e44 {
  strings:
    $key_9e44 = { ca 2c [2] be 34 [2] f9 36 [2] be 27 [2] f0 2b [2] fc 21 [2] eb 2a [2] f0 64 [2] cd }

  condition:
    any of them
}