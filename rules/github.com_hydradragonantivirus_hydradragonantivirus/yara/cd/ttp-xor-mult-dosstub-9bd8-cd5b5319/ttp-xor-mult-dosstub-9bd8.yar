rule TTP_XOR_MULT_DOSStub_9bd8 {
  strings:
    $key_9bd8 = { cf b0 [2] bb a8 [2] fc aa [2] bb bb [2] f5 b7 [2] f9 bd [2] ee b6 [2] f5 f8 [2] c8 }

  condition:
    any of them
}