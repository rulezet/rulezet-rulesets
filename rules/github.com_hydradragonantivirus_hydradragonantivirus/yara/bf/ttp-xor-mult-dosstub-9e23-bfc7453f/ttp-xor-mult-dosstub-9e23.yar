rule TTP_XOR_MULT_DOSStub_9e23 {
  strings:
    $key_9e23 = { ca 4b [2] be 53 [2] f9 51 [2] be 40 [2] f0 4c [2] fc 46 [2] eb 4d [2] f0 03 [2] cd }

  condition:
    any of them
}