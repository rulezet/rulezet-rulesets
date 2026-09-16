rule TTP_XOR_MULT_DOSStub_9e53 {
  strings:
    $key_9e53 = { ca 3b [2] be 23 [2] f9 21 [2] be 30 [2] f0 3c [2] fc 36 [2] eb 3d [2] f0 73 [2] cd }

  condition:
    any of them
}