rule TTP_XOR_MULT_DOSStub_9bd4 {
  strings:
    $key_9bd4 = { cf bc [2] bb a4 [2] fc a6 [2] bb b7 [2] f5 bb [2] f9 b1 [2] ee ba [2] f5 f4 [2] c8 }

  condition:
    any of them
}