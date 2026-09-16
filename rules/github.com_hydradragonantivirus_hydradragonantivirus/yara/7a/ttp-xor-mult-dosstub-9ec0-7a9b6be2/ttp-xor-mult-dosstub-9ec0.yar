rule TTP_XOR_MULT_DOSStub_9ec0 {
  strings:
    $key_9ec0 = { ca a8 [2] be b0 [2] f9 b2 [2] be a3 [2] f0 af [2] fc a5 [2] eb ae [2] f0 e0 [2] cd }

  condition:
    any of them
}