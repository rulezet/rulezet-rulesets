rule TTP_XOR_MULT_DOSStub_9e6a {
  strings:
    $key_9e6a = { ca 02 [2] be 1a [2] f9 18 [2] be 09 [2] f0 05 [2] fc 0f [2] eb 04 [2] f0 4a [2] cd }

  condition:
    any of them
}