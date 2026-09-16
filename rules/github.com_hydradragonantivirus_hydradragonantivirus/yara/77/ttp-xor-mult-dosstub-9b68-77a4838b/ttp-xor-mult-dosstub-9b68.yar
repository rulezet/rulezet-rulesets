rule TTP_XOR_MULT_DOSStub_9b68 {
  strings:
    $key_9b68 = { cf 00 [2] bb 18 [2] fc 1a [2] bb 0b [2] f5 07 [2] f9 0d [2] ee 06 [2] f5 48 [2] c8 }

  condition:
    any of them
}