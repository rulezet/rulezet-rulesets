rule TTP_XOR_MULT_DOSStub_9e79 {
  strings:
    $key_9e79 = { ca 11 [2] be 09 [2] f9 0b [2] be 1a [2] f0 16 [2] fc 1c [2] eb 17 [2] f0 59 [2] cd }

  condition:
    any of them
}