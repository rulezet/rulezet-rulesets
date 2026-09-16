rule TTP_XOR_MULT_DOSStub_9e65 {
  strings:
    $key_9e65 = { ca 0d [2] be 15 [2] f9 17 [2] be 06 [2] f0 0a [2] fc 00 [2] eb 0b [2] f0 45 [2] cd }

  condition:
    any of them
}