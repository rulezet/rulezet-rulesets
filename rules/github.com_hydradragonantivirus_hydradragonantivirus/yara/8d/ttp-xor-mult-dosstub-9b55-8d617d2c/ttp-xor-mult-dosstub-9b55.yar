rule TTP_XOR_MULT_DOSStub_9b55 {
  strings:
    $key_9b55 = { cf 3d [2] bb 25 [2] fc 27 [2] bb 36 [2] f5 3a [2] f9 30 [2] ee 3b [2] f5 75 [2] c8 }

  condition:
    any of them
}