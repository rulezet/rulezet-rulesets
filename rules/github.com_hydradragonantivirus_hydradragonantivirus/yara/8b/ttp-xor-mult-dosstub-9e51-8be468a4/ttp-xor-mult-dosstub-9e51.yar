rule TTP_XOR_MULT_DOSStub_9e51 {
  strings:
    $key_9e51 = { ca 39 [2] be 21 [2] f9 23 [2] be 32 [2] f0 3e [2] fc 34 [2] eb 3f [2] f0 71 [2] cd }

  condition:
    any of them
}