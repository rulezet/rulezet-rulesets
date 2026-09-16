rule TTP_XOR_MULT_DOSStub_9e0c {
  strings:
    $key_9e0c = { ca 64 [2] be 7c [2] f9 7e [2] be 6f [2] f0 63 [2] fc 69 [2] eb 62 [2] f0 2c [2] cd }

  condition:
    any of them
}