rule TTP_XOR_MULT_DOSStub_9b9f {
  strings:
    $key_9b9f = { cf f7 [2] bb ef [2] fc ed [2] bb fc [2] f5 f0 [2] f9 fa [2] ee f1 [2] f5 bf [2] c8 }

  condition:
    any of them
}