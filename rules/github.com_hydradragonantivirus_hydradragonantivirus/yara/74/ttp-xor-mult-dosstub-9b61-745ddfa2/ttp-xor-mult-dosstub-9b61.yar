rule TTP_XOR_MULT_DOSStub_9b61 {
  strings:
    $key_9b61 = { cf 09 [2] bb 11 [2] fc 13 [2] bb 02 [2] f5 0e [2] f9 04 [2] ee 0f [2] f5 41 [2] c8 }

  condition:
    any of them
}