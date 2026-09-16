rule TTP_XOR_MULT_DOSStub_8960 {
  strings:
    $key_8960 = { dd 08 [2] a9 10 [2] ee 12 [2] a9 03 [2] e7 0f [2] eb 05 [2] fc 0e [2] e7 40 [2] da }

  condition:
    any of them
}