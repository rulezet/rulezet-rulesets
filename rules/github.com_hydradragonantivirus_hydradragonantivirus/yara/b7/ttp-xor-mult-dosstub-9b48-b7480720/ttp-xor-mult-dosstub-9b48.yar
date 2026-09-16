rule TTP_XOR_MULT_DOSStub_9b48 {
  strings:
    $key_9b48 = { cf 20 [2] bb 38 [2] fc 3a [2] bb 2b [2] f5 27 [2] f9 2d [2] ee 26 [2] f5 68 [2] c8 }

  condition:
    any of them
}