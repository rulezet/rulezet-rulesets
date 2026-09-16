rule TTP_XOR_MULT_DOSStub_9b09 {
  strings:
    $key_9b09 = { cf 61 [2] bb 79 [2] fc 7b [2] bb 6a [2] f5 66 [2] f9 6c [2] ee 67 [2] f5 29 [2] c8 }

  condition:
    any of them
}