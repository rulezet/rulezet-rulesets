rule TTP_XOR_MULT_DOSStub_9b1c {
  strings:
    $key_9b1c = { cf 74 [2] bb 6c [2] fc 6e [2] bb 7f [2] f5 73 [2] f9 79 [2] ee 72 [2] f5 3c [2] c8 }

  condition:
    any of them
}