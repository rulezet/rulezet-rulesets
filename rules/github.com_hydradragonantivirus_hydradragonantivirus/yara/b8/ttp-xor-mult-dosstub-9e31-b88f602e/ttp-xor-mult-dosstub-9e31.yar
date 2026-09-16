rule TTP_XOR_MULT_DOSStub_9e31 {
  strings:
    $key_9e31 = { ca 59 [2] be 41 [2] f9 43 [2] be 52 [2] f0 5e [2] fc 54 [2] eb 5f [2] f0 11 [2] cd }

  condition:
    any of them
}