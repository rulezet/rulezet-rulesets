rule TTP_XOR_MULT_DOSStub_9e67 {
  strings:
    $key_9e67 = { ca 0f [2] be 17 [2] f9 15 [2] be 04 [2] f0 08 [2] fc 02 [2] eb 09 [2] f0 47 [2] cd }

  condition:
    any of them
}