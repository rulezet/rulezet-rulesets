rule TTP_XOR_MULT_DOSStub_9b14 {
  strings:
    $key_9b14 = { cf 7c [2] bb 64 [2] fc 66 [2] bb 77 [2] f5 7b [2] f9 71 [2] ee 7a [2] f5 34 [2] c8 }

  condition:
    any of them
}