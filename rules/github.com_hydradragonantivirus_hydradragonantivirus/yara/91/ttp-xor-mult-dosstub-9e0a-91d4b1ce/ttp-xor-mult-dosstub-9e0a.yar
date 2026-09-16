rule TTP_XOR_MULT_DOSStub_9e0a {
  strings:
    $key_9e0a = { ca 62 [2] be 7a [2] f9 78 [2] be 69 [2] f0 65 [2] fc 6f [2] eb 64 [2] f0 2a [2] cd }

  condition:
    any of them
}