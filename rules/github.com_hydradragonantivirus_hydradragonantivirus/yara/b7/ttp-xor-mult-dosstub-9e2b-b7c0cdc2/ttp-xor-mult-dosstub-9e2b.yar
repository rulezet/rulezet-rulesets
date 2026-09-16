rule TTP_XOR_MULT_DOSStub_9e2b {
  strings:
    $key_9e2b = { ca 43 [2] be 5b [2] f9 59 [2] be 48 [2] f0 44 [2] fc 4e [2] eb 45 [2] f0 0b [2] cd }

  condition:
    any of them
}