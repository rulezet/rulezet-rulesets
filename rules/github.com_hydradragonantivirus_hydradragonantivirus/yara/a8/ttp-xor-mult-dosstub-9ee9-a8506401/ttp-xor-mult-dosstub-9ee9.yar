rule TTP_XOR_MULT_DOSStub_9ee9 {
  strings:
    $key_9ee9 = { ca 81 [2] be 99 [2] f9 9b [2] be 8a [2] f0 86 [2] fc 8c [2] eb 87 [2] f0 c9 [2] cd }

  condition:
    any of them
}