rule TTP_XOR_MULT_DOSStub_9bd6 {
  strings:
    $key_9bd6 = { cf be [2] bb a6 [2] fc a4 [2] bb b5 [2] f5 b9 [2] f9 b3 [2] ee b8 [2] f5 f6 [2] c8 }

  condition:
    any of them
}