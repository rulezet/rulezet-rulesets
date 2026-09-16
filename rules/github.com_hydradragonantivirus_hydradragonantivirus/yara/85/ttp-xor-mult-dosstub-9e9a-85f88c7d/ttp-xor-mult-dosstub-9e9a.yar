rule TTP_XOR_MULT_DOSStub_9e9a {
  strings:
    $key_9e9a = { ca f2 [2] be ea [2] f9 e8 [2] be f9 [2] f0 f5 [2] fc ff [2] eb f4 [2] f0 ba [2] cd }

  condition:
    any of them
}