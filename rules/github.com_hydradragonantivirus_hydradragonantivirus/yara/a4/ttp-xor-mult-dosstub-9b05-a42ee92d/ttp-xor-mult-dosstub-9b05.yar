rule TTP_XOR_MULT_DOSStub_9b05 {
  strings:
    $key_9b05 = { cf 6d [2] bb 75 [2] fc 77 [2] bb 66 [2] f5 6a [2] f9 60 [2] ee 6b [2] f5 25 [2] c8 }

  condition:
    any of them
}