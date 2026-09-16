rule TTP_XOR_MULT_DOSStub_9b02 {
  strings:
    $key_9b02 = { cf 6a [2] bb 72 [2] fc 70 [2] bb 61 [2] f5 6d [2] f9 67 [2] ee 6c [2] f5 22 [2] c8 }

  condition:
    any of them
}