rule TTP_XOR_MULT_DOSStub_9e29 {
  strings:
    $key_9e29 = { ca 41 [2] be 59 [2] f9 5b [2] be 4a [2] f0 46 [2] fc 4c [2] eb 47 [2] f0 09 [2] cd }

  condition:
    any of them
}