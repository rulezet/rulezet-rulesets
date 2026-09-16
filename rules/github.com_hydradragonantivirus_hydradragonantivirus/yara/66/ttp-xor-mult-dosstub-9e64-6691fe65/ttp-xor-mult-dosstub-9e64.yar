rule TTP_XOR_MULT_DOSStub_9e64 {
  strings:
    $key_9e64 = { ca 0c [2] be 14 [2] f9 16 [2] be 07 [2] f0 0b [2] fc 01 [2] eb 0a [2] f0 44 [2] cd }

  condition:
    any of them
}