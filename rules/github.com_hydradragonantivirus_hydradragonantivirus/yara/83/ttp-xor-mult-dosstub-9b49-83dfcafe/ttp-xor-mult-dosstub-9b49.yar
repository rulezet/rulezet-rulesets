rule TTP_XOR_MULT_DOSStub_9b49 {
  strings:
    $key_9b49 = { cf 21 [2] bb 39 [2] fc 3b [2] bb 2a [2] f5 26 [2] f9 2c [2] ee 27 [2] f5 69 [2] c8 }

  condition:
    any of them
}