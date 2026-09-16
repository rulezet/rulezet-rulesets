rule TTP_XOR_MULT_DOSStub_9b9d {
  strings:
    $key_9b9d = { cf f5 [2] bb ed [2] fc ef [2] bb fe [2] f5 f2 [2] f9 f8 [2] ee f3 [2] f5 bd [2] c8 }

  condition:
    any of them
}