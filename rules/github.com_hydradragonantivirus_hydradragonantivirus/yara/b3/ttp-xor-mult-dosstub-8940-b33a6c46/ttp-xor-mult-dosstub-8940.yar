rule TTP_XOR_MULT_DOSStub_8940 {
  strings:
    $key_8940 = { dd 28 [2] a9 30 [2] ee 32 [2] a9 23 [2] e7 2f [2] eb 25 [2] fc 2e [2] e7 60 [2] da }

  condition:
    any of them
}