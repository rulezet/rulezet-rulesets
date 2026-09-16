rule TTP_XOR_MULT_DOSStub_9ee8 {
  strings:
    $key_9ee8 = { ca 80 [2] be 98 [2] f9 9a [2] be 8b [2] f0 87 [2] fc 8d [2] eb 86 [2] f0 c8 [2] cd }

  condition:
    any of them
}