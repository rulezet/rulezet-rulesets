rule TTP_XOR_MULT_DOSStub_9e7a {
  strings:
    $key_9e7a = { ca 12 [2] be 0a [2] f9 08 [2] be 19 [2] f0 15 [2] fc 1f [2] eb 14 [2] f0 5a [2] cd }

  condition:
    any of them
}