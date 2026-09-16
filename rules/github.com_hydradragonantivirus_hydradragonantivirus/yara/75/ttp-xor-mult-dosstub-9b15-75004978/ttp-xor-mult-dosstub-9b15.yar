rule TTP_XOR_MULT_DOSStub_9b15 {
  strings:
    $key_9b15 = { cf 7d [2] bb 65 [2] fc 67 [2] bb 76 [2] f5 7a [2] f9 70 [2] ee 7b [2] f5 35 [2] c8 }

  condition:
    any of them
}