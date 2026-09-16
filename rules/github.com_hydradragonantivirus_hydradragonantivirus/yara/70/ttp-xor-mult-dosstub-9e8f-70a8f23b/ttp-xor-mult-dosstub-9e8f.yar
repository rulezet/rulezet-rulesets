rule TTP_XOR_MULT_DOSStub_9e8f {
  strings:
    $key_9e8f = { ca e7 [2] be ff [2] f9 fd [2] be ec [2] f0 e0 [2] fc ea [2] eb e1 [2] f0 af [2] cd }

  condition:
    any of them
}