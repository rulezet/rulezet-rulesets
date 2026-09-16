rule TTP_XOR_MULT_DOSStub_8904 {
  strings:
    $key_8904 = { dd 6c [2] a9 74 [2] ee 76 [2] a9 67 [2] e7 6b [2] eb 61 [2] fc 6a [2] e7 24 [2] da }

  condition:
    any of them
}