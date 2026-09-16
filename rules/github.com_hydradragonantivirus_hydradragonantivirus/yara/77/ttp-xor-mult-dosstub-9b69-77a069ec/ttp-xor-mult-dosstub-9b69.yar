rule TTP_XOR_MULT_DOSStub_9b69 {
  strings:
    $key_9b69 = { cf 01 [2] bb 19 [2] fc 1b [2] bb 0a [2] f5 06 [2] f9 0c [2] ee 07 [2] f5 49 [2] c8 }

  condition:
    any of them
}