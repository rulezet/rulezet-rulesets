rule TTP_XOR_MULT_DOSStub_9ef2 {
  strings:
    $key_9ef2 = { ca 9a [2] be 82 [2] f9 80 [2] be 91 [2] f0 9d [2] fc 97 [2] eb 9c [2] f0 d2 [2] cd }

  condition:
    any of them
}