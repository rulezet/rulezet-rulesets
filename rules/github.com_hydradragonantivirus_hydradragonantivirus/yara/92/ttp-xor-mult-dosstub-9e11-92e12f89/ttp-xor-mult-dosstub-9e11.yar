rule TTP_XOR_MULT_DOSStub_9e11 {
  strings:
    $key_9e11 = { ca 79 [2] be 61 [2] f9 63 [2] be 72 [2] f0 7e [2] fc 74 [2] eb 7f [2] f0 31 [2] cd }

  condition:
    any of them
}