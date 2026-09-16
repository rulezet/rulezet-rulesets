rule TTP_XOR_MULT_DOSStub_9e78 {
  strings:
    $key_9e78 = { ca 10 [2] be 08 [2] f9 0a [2] be 1b [2] f0 17 [2] fc 1d [2] eb 16 [2] f0 58 [2] cd }

  condition:
    any of them
}