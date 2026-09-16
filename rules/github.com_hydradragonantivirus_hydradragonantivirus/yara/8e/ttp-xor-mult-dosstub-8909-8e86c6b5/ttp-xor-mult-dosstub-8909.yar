rule TTP_XOR_MULT_DOSStub_8909 {
  strings:
    $key_8909 = { dd 61 [2] a9 79 [2] ee 7b [2] a9 6a [2] e7 66 [2] eb 6c [2] fc 67 [2] e7 29 [2] da }

  condition:
    any of them
}