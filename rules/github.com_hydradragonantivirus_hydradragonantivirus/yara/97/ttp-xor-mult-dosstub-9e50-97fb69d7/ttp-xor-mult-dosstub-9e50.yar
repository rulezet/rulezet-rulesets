rule TTP_XOR_MULT_DOSStub_9e50 {
  strings:
    $key_9e50 = { ca 38 [2] be 20 [2] f9 22 [2] be 33 [2] f0 3f [2] fc 35 [2] eb 3e [2] f0 70 [2] cd }

  condition:
    any of them
}