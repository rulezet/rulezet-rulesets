rule TTP_XOR_MULT_DOSStub_8941 {
  strings:
    $key_8941 = { dd 29 [2] a9 31 [2] ee 33 [2] a9 22 [2] e7 2e [2] eb 24 [2] fc 2f [2] e7 61 [2] da }

  condition:
    any of them
}