rule TTP_XOR_MULT_DOSStub_9e77 {
  strings:
    $key_9e77 = { ca 1f [2] be 07 [2] f9 05 [2] be 14 [2] f0 18 [2] fc 12 [2] eb 19 [2] f0 57 [2] cd }

  condition:
    any of them
}