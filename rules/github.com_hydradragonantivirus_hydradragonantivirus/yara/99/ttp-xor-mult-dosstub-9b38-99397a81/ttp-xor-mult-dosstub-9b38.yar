rule TTP_XOR_MULT_DOSStub_9b38 {
  strings:
    $key_9b38 = { cf 50 [2] bb 48 [2] fc 4a [2] bb 5b [2] f5 57 [2] f9 5d [2] ee 56 [2] f5 18 [2] c8 }

  condition:
    any of them
}