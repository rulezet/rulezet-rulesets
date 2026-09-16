rule TTP_XOR_MULT_DOSStub_9e18 {
  strings:
    $key_9e18 = { ca 70 [2] be 68 [2] f9 6a [2] be 7b [2] f0 77 [2] fc 7d [2] eb 76 [2] f0 38 [2] cd }

  condition:
    any of them
}