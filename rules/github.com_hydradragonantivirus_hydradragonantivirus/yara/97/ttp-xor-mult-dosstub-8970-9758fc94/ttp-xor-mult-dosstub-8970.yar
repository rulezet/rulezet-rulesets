rule TTP_XOR_MULT_DOSStub_8970 {
  strings:
    $key_8970 = { dd 18 [2] a9 00 [2] ee 02 [2] a9 13 [2] e7 1f [2] eb 15 [2] fc 1e [2] e7 50 [2] da }

  condition:
    any of them
}