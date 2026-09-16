rule TTP_XOR_MULT_DOSStub_9b93 {
  strings:
    $key_9b93 = { cf fb [2] bb e3 [2] fc e1 [2] bb f0 [2] f5 fc [2] f9 f6 [2] ee fd [2] f5 b3 [2] c8 }

  condition:
    any of them
}