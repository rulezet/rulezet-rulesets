rule TTP_XOR_MULT_DOSStub_9e6b {
  strings:
    $key_9e6b = { ca 03 [2] be 1b [2] f9 19 [2] be 08 [2] f0 04 [2] fc 0e [2] eb 05 [2] f0 4b [2] cd }

  condition:
    any of them
}