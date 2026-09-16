rule TTP_XOR_MULT_DOSStub_9e60 {
  strings:
    $key_9e60 = { ca 08 [2] be 10 [2] f9 12 [2] be 03 [2] f0 0f [2] fc 05 [2] eb 0e [2] f0 40 [2] cd }

  condition:
    any of them
}