rule TTP_XOR_MULT_DOSStub_9e92 {
  strings:
    $key_9e92 = { ca fa [2] be e2 [2] f9 e0 [2] be f1 [2] f0 fd [2] fc f7 [2] eb fc [2] f0 b2 [2] cd }

  condition:
    any of them
}