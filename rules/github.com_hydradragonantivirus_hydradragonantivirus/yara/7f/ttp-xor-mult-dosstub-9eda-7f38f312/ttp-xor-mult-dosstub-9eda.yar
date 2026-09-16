rule TTP_XOR_MULT_DOSStub_9eda {
  strings:
    $key_9eda = { ca b2 [2] be aa [2] f9 a8 [2] be b9 [2] f0 b5 [2] fc bf [2] eb b4 [2] f0 fa [2] cd }

  condition:
    any of them
}