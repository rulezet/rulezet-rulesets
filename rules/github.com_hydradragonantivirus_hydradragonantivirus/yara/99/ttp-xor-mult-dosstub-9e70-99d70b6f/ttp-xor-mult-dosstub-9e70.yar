rule TTP_XOR_MULT_DOSStub_9e70 {
  strings:
    $key_9e70 = { ca 18 [2] be 00 [2] f9 02 [2] be 13 [2] f0 1f [2] fc 15 [2] eb 1e [2] f0 50 [2] cd }

  condition:
    any of them
}