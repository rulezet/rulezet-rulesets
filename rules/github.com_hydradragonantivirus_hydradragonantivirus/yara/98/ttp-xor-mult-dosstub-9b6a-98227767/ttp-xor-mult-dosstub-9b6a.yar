rule TTP_XOR_MULT_DOSStub_9b6a {
  strings:
    $key_9b6a = { cf 02 [2] bb 1a [2] fc 18 [2] bb 09 [2] f5 05 [2] f9 0f [2] ee 04 [2] f5 4a [2] c8 }

  condition:
    any of them
}