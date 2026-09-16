rule TTP_XOR_MULT_DOSStub_897c {
  strings:
    $key_897c = { dd 14 [2] a9 0c [2] ee 0e [2] a9 1f [2] e7 13 [2] eb 19 [2] fc 12 [2] e7 5c [2] da }

  condition:
    any of them
}