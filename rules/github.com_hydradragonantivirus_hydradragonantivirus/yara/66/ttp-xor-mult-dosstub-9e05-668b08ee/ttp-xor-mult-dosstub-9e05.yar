rule TTP_XOR_MULT_DOSStub_9e05 {
  strings:
    $key_9e05 = { ca 6d [2] be 75 [2] f9 77 [2] be 66 [2] f0 6a [2] fc 60 [2] eb 6b [2] f0 25 [2] cd }

  condition:
    any of them
}