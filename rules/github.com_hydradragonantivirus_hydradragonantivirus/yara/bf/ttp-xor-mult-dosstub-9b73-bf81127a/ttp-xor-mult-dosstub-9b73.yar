rule TTP_XOR_MULT_DOSStub_9b73 {
  strings:
    $key_9b73 = { cf 1b [2] bb 03 [2] fc 01 [2] bb 10 [2] f5 1c [2] f9 16 [2] ee 1d [2] f5 53 [2] c8 }

  condition:
    any of them
}