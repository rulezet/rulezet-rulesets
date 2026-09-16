rule TTP_XOR_MULT_DOSStub_9e1a {
  strings:
    $key_9e1a = { ca 72 [2] be 6a [2] f9 68 [2] be 79 [2] f0 75 [2] fc 7f [2] eb 74 [2] f0 3a [2] cd }

  condition:
    any of them
}