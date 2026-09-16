rule TTP_XOR_MULT_DOSStub_9b85 {
  strings:
    $key_9b85 = { cf ed [2] bb f5 [2] fc f7 [2] bb e6 [2] f5 ea [2] f9 e0 [2] ee eb [2] f5 a5 [2] c8 }

  condition:
    any of them
}