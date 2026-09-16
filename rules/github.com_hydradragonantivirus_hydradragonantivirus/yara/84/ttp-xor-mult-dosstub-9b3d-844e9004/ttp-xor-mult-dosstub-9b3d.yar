rule TTP_XOR_MULT_DOSStub_9b3d {
  strings:
    $key_9b3d = { cf 55 [2] bb 4d [2] fc 4f [2] bb 5e [2] f5 52 [2] f9 58 [2] ee 53 [2] f5 1d [2] c8 }

  condition:
    any of them
}