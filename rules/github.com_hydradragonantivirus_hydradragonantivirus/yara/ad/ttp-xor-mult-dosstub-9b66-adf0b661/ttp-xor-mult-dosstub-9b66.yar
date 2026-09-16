rule TTP_XOR_MULT_DOSStub_9b66 {
  strings:
    $key_9b66 = { cf 0e [2] bb 16 [2] fc 14 [2] bb 05 [2] f5 09 [2] f9 03 [2] ee 08 [2] f5 46 [2] c8 }

  condition:
    any of them
}