rule TTP_XOR_MULT_DOSStub_9b1b {
  strings:
    $key_9b1b = { cf 73 [2] bb 6b [2] fc 69 [2] bb 78 [2] f5 74 [2] f9 7e [2] ee 75 [2] f5 3b [2] c8 }

  condition:
    any of them
}