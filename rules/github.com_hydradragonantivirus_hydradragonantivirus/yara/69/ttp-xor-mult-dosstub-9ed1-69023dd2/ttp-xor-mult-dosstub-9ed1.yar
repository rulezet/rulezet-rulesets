rule TTP_XOR_MULT_DOSStub_9ed1 {
  strings:
    $key_9ed1 = { ca b9 [2] be a1 [2] f9 a3 [2] be b2 [2] f0 be [2] fc b4 [2] eb bf [2] f0 f1 [2] cd }

  condition:
    any of them
}