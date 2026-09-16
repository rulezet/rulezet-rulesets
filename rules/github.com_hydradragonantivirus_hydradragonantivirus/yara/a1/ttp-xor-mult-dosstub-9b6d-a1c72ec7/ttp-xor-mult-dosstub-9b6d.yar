rule TTP_XOR_MULT_DOSStub_9b6d {
  strings:
    $key_9b6d = { cf 05 [2] bb 1d [2] fc 1f [2] bb 0e [2] f5 02 [2] f9 08 [2] ee 03 [2] f5 4d [2] c8 }

  condition:
    any of them
}