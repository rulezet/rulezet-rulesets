rule TTP_XOR_MULT_DOSStub_9b16 {
  strings:
    $key_9b16 = { cf 7e [2] bb 66 [2] fc 64 [2] bb 75 [2] f5 79 [2] f9 73 [2] ee 78 [2] f5 36 [2] c8 }

  condition:
    any of them
}