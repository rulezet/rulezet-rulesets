rule TTP_XOR_MULT_DOSStub_9e73 {
  strings:
    $key_9e73 = { ca 1b [2] be 03 [2] f9 01 [2] be 10 [2] f0 1c [2] fc 16 [2] eb 1d [2] f0 53 [2] cd }

  condition:
    any of them
}