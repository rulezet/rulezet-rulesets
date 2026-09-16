rule TTP_XOR_MULT_DOSStub_9ef0 {
  strings:
    $key_9ef0 = { ca 98 [2] be 80 [2] f9 82 [2] be 93 [2] f0 9f [2] fc 95 [2] eb 9e [2] f0 d0 [2] cd }

  condition:
    any of them
}