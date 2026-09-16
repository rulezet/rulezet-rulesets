rule TTP_XOR_MULT_DOSStub_9bd2 {
  strings:
    $key_9bd2 = { cf ba [2] bb a2 [2] fc a0 [2] bb b1 [2] f5 bd [2] f9 b7 [2] ee bc [2] f5 f2 [2] c8 }

  condition:
    any of them
}