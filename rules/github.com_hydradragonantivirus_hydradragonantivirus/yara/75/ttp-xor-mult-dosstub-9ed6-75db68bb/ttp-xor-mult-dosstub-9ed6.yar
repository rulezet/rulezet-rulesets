rule TTP_XOR_MULT_DOSStub_9ed6 {
  strings:
    $key_9ed6 = { ca be [2] be a6 [2] f9 a4 [2] be b5 [2] f0 b9 [2] fc b3 [2] eb b8 [2] f0 f6 [2] cd }

  condition:
    any of them
}