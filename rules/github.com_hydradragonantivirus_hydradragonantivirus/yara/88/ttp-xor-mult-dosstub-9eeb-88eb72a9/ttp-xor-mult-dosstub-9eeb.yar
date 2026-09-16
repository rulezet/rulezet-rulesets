rule TTP_XOR_MULT_DOSStub_9eeb {
  strings:
    $key_9eeb = { ca 83 [2] be 9b [2] f9 99 [2] be 88 [2] f0 84 [2] fc 8e [2] eb 85 [2] f0 cb [2] cd }

  condition:
    any of them
}