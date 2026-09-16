rule TTP_XOR_MULT_DOSStub_897f {
  strings:
    $key_897f = { dd 17 [2] a9 0f [2] ee 0d [2] a9 1c [2] e7 10 [2] eb 1a [2] fc 11 [2] e7 5f [2] da }

  condition:
    any of them
}