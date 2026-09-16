rule TTP_XOR_MULT_DOSStub_9ef5 {
  strings:
    $key_9ef5 = { ca 9d [2] be 85 [2] f9 87 [2] be 96 [2] f0 9a [2] fc 90 [2] eb 9b [2] f0 d5 [2] cd }

  condition:
    any of them
}