rule TTP_XOR_MULT_DOSStub_9ebd {
  strings:
    $key_9ebd = { ca d5 [2] be cd [2] f9 cf [2] be de [2] f0 d2 [2] fc d8 [2] eb d3 [2] f0 9d [2] cd }

  condition:
    any of them
}