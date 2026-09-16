rule TTP_XOR_MULT_DOSStub_9ef3 {
  strings:
    $key_9ef3 = { ca 9b [2] be 83 [2] f9 81 [2] be 90 [2] f0 9c [2] fc 96 [2] eb 9d [2] f0 d3 [2] cd }

  condition:
    any of them
}