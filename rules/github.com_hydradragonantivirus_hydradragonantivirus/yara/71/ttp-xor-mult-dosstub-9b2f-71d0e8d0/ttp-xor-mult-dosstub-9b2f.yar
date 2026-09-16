rule TTP_XOR_MULT_DOSStub_9b2f {
  strings:
    $key_9b2f = { cf 47 [2] bb 5f [2] fc 5d [2] bb 4c [2] f5 40 [2] f9 4a [2] ee 41 [2] f5 0f [2] c8 }

  condition:
    any of them
}