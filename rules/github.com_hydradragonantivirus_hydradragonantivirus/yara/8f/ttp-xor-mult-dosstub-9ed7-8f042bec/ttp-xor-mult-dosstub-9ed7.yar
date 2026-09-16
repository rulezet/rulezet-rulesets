rule TTP_XOR_MULT_DOSStub_9ed7 {
  strings:
    $key_9ed7 = { ca bf [2] be a7 [2] f9 a5 [2] be b4 [2] f0 b8 [2] fc b2 [2] eb b9 [2] f0 f7 [2] cd }

  condition:
    any of them
}