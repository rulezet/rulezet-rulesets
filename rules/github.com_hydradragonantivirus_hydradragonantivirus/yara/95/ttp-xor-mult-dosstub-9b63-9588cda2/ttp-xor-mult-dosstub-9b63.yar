rule TTP_XOR_MULT_DOSStub_9b63 {
  strings:
    $key_9b63 = { cf 0b [2] bb 13 [2] fc 11 [2] bb 00 [2] f5 0c [2] f9 06 [2] ee 0d [2] f5 43 [2] c8 }

  condition:
    any of them
}