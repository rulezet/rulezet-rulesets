rule TTP_XOR_MULT_DOSStub_9e54 {
  strings:
    $key_9e54 = { ca 3c [2] be 24 [2] f9 26 [2] be 37 [2] f0 3b [2] fc 31 [2] eb 3a [2] f0 74 [2] cd }

  condition:
    any of them
}