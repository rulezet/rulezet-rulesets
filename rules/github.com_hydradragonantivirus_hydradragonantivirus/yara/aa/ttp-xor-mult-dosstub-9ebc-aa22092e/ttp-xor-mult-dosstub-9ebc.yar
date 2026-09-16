rule TTP_XOR_MULT_DOSStub_9ebc {
  strings:
    $key_9ebc = { ca d4 [2] be cc [2] f9 ce [2] be df [2] f0 d3 [2] fc d9 [2] eb d2 [2] f0 9c [2] cd }

  condition:
    any of them
}