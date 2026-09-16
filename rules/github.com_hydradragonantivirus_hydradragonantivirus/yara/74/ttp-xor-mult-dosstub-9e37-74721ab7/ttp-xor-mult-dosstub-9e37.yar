rule TTP_XOR_MULT_DOSStub_9e37 {
  strings:
    $key_9e37 = { ca 5f [2] be 47 [2] f9 45 [2] be 54 [2] f0 58 [2] fc 52 [2] eb 59 [2] f0 17 [2] cd }

  condition:
    any of them
}