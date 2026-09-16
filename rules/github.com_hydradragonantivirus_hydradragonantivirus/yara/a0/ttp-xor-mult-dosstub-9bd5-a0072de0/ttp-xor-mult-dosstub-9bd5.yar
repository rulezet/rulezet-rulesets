rule TTP_XOR_MULT_DOSStub_9bd5 {
  strings:
    $key_9bd5 = { cf bd [2] bb a5 [2] fc a7 [2] bb b6 [2] f5 ba [2] f9 b0 [2] ee bb [2] f5 f5 [2] c8 }

  condition:
    any of them
}