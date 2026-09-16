rule TTP_XOR_MULT_DOSStub_9ee4 {
  strings:
    $key_9ee4 = { ca 8c [2] be 94 [2] f9 96 [2] be 87 [2] f0 8b [2] fc 81 [2] eb 8a [2] f0 c4 [2] cd }

  condition:
    any of them
}