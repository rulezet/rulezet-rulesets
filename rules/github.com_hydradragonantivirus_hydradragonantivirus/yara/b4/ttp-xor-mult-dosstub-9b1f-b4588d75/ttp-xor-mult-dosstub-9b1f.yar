rule TTP_XOR_MULT_DOSStub_9b1f {
  strings:
    $key_9b1f = { cf 77 [2] bb 6f [2] fc 6d [2] bb 7c [2] f5 70 [2] f9 7a [2] ee 71 [2] f5 3f [2] c8 }

  condition:
    any of them
}