rule TTP_XOR_MULT_DOSStub_8919 {
  strings:
    $key_8919 = { dd 71 [2] a9 69 [2] ee 6b [2] a9 7a [2] e7 76 [2] eb 7c [2] fc 77 [2] e7 39 [2] da }

  condition:
    any of them
}