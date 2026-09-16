rule TTP_XOR_MULT_DOSStub_8906 {
  strings:
    $key_8906 = { dd 6e [2] a9 76 [2] ee 74 [2] a9 65 [2] e7 69 [2] eb 63 [2] fc 68 [2] e7 26 [2] da }

  condition:
    any of them
}