rule TTP_XOR_MULT_DOSStub_9bd7 {
  strings:
    $key_9bd7 = { cf bf [2] bb a7 [2] fc a5 [2] bb b4 [2] f5 b8 [2] f9 b2 [2] ee b9 [2] f5 f7 [2] c8 }

  condition:
    any of them
}