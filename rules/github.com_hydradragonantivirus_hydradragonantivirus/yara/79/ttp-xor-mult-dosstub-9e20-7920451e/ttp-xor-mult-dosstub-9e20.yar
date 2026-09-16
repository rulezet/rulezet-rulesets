rule TTP_XOR_MULT_DOSStub_9e20 {
  strings:
    $key_9e20 = { ca 48 [2] be 50 [2] f9 52 [2] be 43 [2] f0 4f [2] fc 45 [2] eb 4e [2] f0 00 [2] cd }

  condition:
    any of them
}