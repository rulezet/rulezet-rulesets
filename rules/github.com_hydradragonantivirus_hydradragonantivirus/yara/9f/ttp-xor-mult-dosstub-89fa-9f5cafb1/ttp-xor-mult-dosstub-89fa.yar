rule TTP_XOR_MULT_DOSStub_89fa {
  strings:
    $key_89fa = { dd 92 [2] a9 8a [2] ee 88 [2] a9 99 [2] e7 95 [2] eb 9f [2] fc 94 [2] e7 da [2] da }

  condition:
    any of them
}