rule TTP_XOR_MULT_DOSStub_9b75 {
  strings:
    $key_9b75 = { cf 1d [2] bb 05 [2] fc 07 [2] bb 16 [2] f5 1a [2] f9 10 [2] ee 1b [2] f5 55 [2] c8 }

  condition:
    any of them
}