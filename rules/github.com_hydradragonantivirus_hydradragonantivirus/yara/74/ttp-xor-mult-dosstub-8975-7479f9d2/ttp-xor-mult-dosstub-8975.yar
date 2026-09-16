rule TTP_XOR_MULT_DOSStub_8975 {
  strings:
    $key_8975 = { dd 1d [2] a9 05 [2] ee 07 [2] a9 16 [2] e7 1a [2] eb 10 [2] fc 1b [2] e7 55 [2] da }

  condition:
    any of them
}