rule TTP_XOR_MULT_DOSStub_9e19 {
  strings:
    $key_9e19 = { ca 71 [2] be 69 [2] f9 6b [2] be 7a [2] f0 76 [2] fc 7c [2] eb 77 [2] f0 39 [2] cd }

  condition:
    any of them
}