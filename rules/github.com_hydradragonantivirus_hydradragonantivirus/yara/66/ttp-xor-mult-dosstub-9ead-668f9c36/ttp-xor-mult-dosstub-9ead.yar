rule TTP_XOR_MULT_DOSStub_9ead {
  strings:
    $key_9ead = { ca c5 [2] be dd [2] f9 df [2] be ce [2] f0 c2 [2] fc c8 [2] eb c3 [2] f0 8d [2] cd }

  condition:
    any of them
}