rule TTP_XOR_MULT_DOSStub_9e36 {
  strings:
    $key_9e36 = { ca 5e [2] be 46 [2] f9 44 [2] be 55 [2] f0 59 [2] fc 53 [2] eb 58 [2] f0 16 [2] cd }

  condition:
    any of them
}