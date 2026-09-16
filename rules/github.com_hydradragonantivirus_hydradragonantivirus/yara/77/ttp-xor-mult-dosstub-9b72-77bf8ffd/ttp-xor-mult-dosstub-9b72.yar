rule TTP_XOR_MULT_DOSStub_9b72 {
  strings:
    $key_9b72 = { cf 1a [2] bb 02 [2] fc 00 [2] bb 11 [2] f5 1d [2] f9 17 [2] ee 1c [2] f5 52 [2] c8 }

  condition:
    any of them
}