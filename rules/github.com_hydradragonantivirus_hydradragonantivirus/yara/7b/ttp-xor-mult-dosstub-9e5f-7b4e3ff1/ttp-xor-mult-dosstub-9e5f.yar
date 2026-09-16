rule TTP_XOR_MULT_DOSStub_9e5f {
  strings:
    $key_9e5f = { ca 37 [2] be 2f [2] f9 2d [2] be 3c [2] f0 30 [2] fc 3a [2] eb 31 [2] f0 7f [2] cd }

  condition:
    any of them
}