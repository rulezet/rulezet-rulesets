rule TTP_XOR_MULT_DOSStub_9ef1 {
  strings:
    $key_9ef1 = { ca 99 [2] be 81 [2] f9 83 [2] be 92 [2] f0 9e [2] fc 94 [2] eb 9f [2] f0 d1 [2] cd }

  condition:
    any of them
}