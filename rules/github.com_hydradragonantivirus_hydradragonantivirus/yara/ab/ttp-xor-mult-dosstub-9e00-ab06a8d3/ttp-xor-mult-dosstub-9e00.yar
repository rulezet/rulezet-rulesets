rule TTP_XOR_MULT_DOSStub_9e00 {
  strings:
    $key_9e00 = { ca 68 [2] be 70 [2] f9 72 [2] be 63 [2] f0 6f [2] fc 65 [2] eb 6e [2] f0 20 [2] cd }

  condition:
    any of them
}