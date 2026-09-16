rule TTP_XOR_MULT_DOSStub_9bc3 {
  strings:
    $key_9bc3 = { cf ab [2] bb b3 [2] fc b1 [2] bb a0 [2] f5 ac [2] f9 a6 [2] ee ad [2] f5 e3 [2] c8 }

  condition:
    any of them
}