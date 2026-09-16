rule TTP_XOR_MULT_DOSStub_8947 {
  strings:
    $key_8947 = { dd 2f [2] a9 37 [2] ee 35 [2] a9 24 [2] e7 28 [2] eb 22 [2] fc 29 [2] e7 67 [2] da }

  condition:
    any of them
}