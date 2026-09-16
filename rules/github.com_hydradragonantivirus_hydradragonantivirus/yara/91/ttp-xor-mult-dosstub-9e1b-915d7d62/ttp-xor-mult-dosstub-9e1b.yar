rule TTP_XOR_MULT_DOSStub_9e1b {
  strings:
    $key_9e1b = { ca 73 [2] be 6b [2] f9 69 [2] be 78 [2] f0 74 [2] fc 7e [2] eb 75 [2] f0 3b [2] cd }

  condition:
    any of them
}