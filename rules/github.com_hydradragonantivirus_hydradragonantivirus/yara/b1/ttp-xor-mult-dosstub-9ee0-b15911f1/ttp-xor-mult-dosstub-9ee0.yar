rule TTP_XOR_MULT_DOSStub_9ee0 {
  strings:
    $key_9ee0 = { ca 88 [2] be 90 [2] f9 92 [2] be 83 [2] f0 8f [2] fc 85 [2] eb 8e [2] f0 c0 [2] cd }

  condition:
    any of them
}