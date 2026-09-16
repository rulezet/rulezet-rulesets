rule TTP_XOR_MULT_DOSStub_9e5b {
  strings:
    $key_9e5b = { ca 33 [2] be 2b [2] f9 29 [2] be 38 [2] f0 34 [2] fc 3e [2] eb 35 [2] f0 7b [2] cd }

  condition:
    any of them
}