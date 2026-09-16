rule TTP_XOR_MULT_DOSStub_9e22 {
  strings:
    $key_9e22 = { ca 4a [2] be 52 [2] f9 50 [2] be 41 [2] f0 4d [2] fc 47 [2] eb 4c [2] f0 02 [2] cd }

  condition:
    any of them
}