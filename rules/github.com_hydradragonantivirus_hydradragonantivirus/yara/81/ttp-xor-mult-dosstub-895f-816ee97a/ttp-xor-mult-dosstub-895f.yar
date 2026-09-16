rule TTP_XOR_MULT_DOSStub_895f {
  strings:
    $key_895f = { dd 37 [2] a9 2f [2] ee 2d [2] a9 3c [2] e7 30 [2] eb 3a [2] fc 31 [2] e7 7f [2] da }

  condition:
    any of them
}