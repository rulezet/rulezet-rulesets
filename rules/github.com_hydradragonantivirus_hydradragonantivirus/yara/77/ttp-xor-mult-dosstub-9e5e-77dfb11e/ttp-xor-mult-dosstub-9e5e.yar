rule TTP_XOR_MULT_DOSStub_9e5e {
  strings:
    $key_9e5e = { ca 36 [2] be 2e [2] f9 2c [2] be 3d [2] f0 31 [2] fc 3b [2] eb 30 [2] f0 7e [2] cd }

  condition:
    any of them
}