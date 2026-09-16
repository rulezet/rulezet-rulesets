rule TTP_XOR_MULT_DOSStub_8954 {
  strings:
    $key_8954 = { dd 3c [2] a9 24 [2] ee 26 [2] a9 37 [2] e7 3b [2] eb 31 [2] fc 3a [2] e7 74 [2] da }

  condition:
    any of them
}