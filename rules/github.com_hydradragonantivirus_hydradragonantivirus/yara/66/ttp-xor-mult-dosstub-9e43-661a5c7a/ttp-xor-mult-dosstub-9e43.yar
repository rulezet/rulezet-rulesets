rule TTP_XOR_MULT_DOSStub_9e43 {
  strings:
    $key_9e43 = { ca 2b [2] be 33 [2] f9 31 [2] be 20 [2] f0 2c [2] fc 26 [2] eb 2d [2] f0 63 [2] cd }

  condition:
    any of them
}