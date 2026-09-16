rule TTP_XOR_MULT_DOSStub_8978 {
  strings:
    $key_8978 = { dd 10 [2] a9 08 [2] ee 0a [2] a9 1b [2] e7 17 [2] eb 1d [2] fc 16 [2] e7 58 [2] da }

  condition:
    any of them
}