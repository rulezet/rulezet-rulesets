rule TTP_XOR_MULT_DOSStub_9b33 {
  strings:
    $key_9b33 = { cf 5b [2] bb 43 [2] fc 41 [2] bb 50 [2] f5 5c [2] f9 56 [2] ee 5d [2] f5 13 [2] c8 }

  condition:
    any of them
}