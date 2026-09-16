rule TTP_XOR_MULT_DOSStub_9be8 {
  strings:
    $key_9be8 = { cf 80 [2] bb 98 [2] fc 9a [2] bb 8b [2] f5 87 [2] f9 8d [2] ee 86 [2] f5 c8 [2] c8 }

  condition:
    any of them
}