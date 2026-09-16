rule TTP_XOR_MULT_DOSStub_9b25 {
  strings:
    $key_9b25 = { cf 4d [2] bb 55 [2] fc 57 [2] bb 46 [2] f5 4a [2] f9 40 [2] ee 4b [2] f5 05 [2] c8 }

  condition:
    any of them
}