rule TTP_XOR_MULT_DOSStub_9b28 {
  strings:
    $key_9b28 = { cf 40 [2] bb 58 [2] fc 5a [2] bb 4b [2] f5 47 [2] f9 4d [2] ee 46 [2] f5 08 [2] c8 }

  condition:
    any of them
}