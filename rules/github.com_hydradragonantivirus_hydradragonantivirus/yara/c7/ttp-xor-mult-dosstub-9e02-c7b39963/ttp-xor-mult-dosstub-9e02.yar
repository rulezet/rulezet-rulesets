rule TTP_XOR_MULT_DOSStub_9e02 {
  strings:
    $key_9e02 = { ca 6a [2] be 72 [2] f9 70 [2] be 61 [2] f0 6d [2] fc 67 [2] eb 6c [2] f0 22 [2] cd }

  condition:
    any of them
}