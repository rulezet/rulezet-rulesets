rule TTP_XOR_MULT_DOSStub_9b90 {
  strings:
    $key_9b90 = { cf f8 [2] bb e0 [2] fc e2 [2] bb f3 [2] f5 ff [2] f9 f5 [2] ee fe [2] f5 b0 [2] c8 }

  condition:
    any of them
}