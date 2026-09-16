rule TTP_XOR_MULT_DOSStub_9e38 {
  strings:
    $key_9e38 = { ca 50 [2] be 48 [2] f9 4a [2] be 5b [2] f0 57 [2] fc 5d [2] eb 56 [2] f0 18 [2] cd }

  condition:
    any of them
}