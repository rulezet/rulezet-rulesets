rule TTP_XOR_MULT_DOSStub_8968 {
  strings:
    $key_8968 = { dd 00 [2] a9 18 [2] ee 1a [2] a9 0b [2] e7 07 [2] eb 0d [2] fc 06 [2] e7 48 [2] da }

  condition:
    any of them
}