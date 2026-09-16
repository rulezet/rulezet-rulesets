rule TTP_XOR_MULT_DOSStub_9b21 {
  strings:
    $key_9b21 = { cf 49 [2] bb 51 [2] fc 53 [2] bb 42 [2] f5 4e [2] f9 44 [2] ee 4f [2] f5 01 [2] c8 }

  condition:
    any of them
}