rule TTP_XOR_MULT_DOSStub_9be6 {
  strings:
    $key_9be6 = { cf 8e [2] bb 96 [2] fc 94 [2] bb 85 [2] f5 89 [2] f9 83 [2] ee 88 [2] f5 c6 [2] c8 }

  condition:
    any of them
}