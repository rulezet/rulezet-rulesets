rule TTP_XOR_MULT_DOSStub_8946 {
  strings:
    $key_8946 = { dd 2e [2] a9 36 [2] ee 34 [2] a9 25 [2] e7 29 [2] eb 23 [2] fc 28 [2] e7 66 [2] da }

  condition:
    any of them
}