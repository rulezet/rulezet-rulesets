rule TTP_XOR_MULT_DOSStub_9e15 {
  strings:
    $key_9e15 = { ca 7d [2] be 65 [2] f9 67 [2] be 76 [2] f0 7a [2] fc 70 [2] eb 7b [2] f0 35 [2] cd }

  condition:
    any of them
}