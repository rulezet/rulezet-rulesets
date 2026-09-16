rule TTP_XOR_MULT_DOSStub_9e25 {
  strings:
    $key_9e25 = { ca 4d [2] be 55 [2] f9 57 [2] be 46 [2] f0 4a [2] fc 40 [2] eb 4b [2] f0 05 [2] cd }

  condition:
    any of them
}