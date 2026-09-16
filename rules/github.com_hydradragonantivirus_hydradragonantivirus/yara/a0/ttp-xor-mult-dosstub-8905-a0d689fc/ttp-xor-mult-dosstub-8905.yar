rule TTP_XOR_MULT_DOSStub_8905 {
  strings:
    $key_8905 = { dd 6d [2] a9 75 [2] ee 77 [2] a9 66 [2] e7 6a [2] eb 60 [2] fc 6b [2] e7 25 [2] da }

  condition:
    any of them
}