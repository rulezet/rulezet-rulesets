rule TTP_XOR_MULT_DOSStub_895a {
  strings:
    $key_895a = { dd 32 [2] a9 2a [2] ee 28 [2] a9 39 [2] e7 35 [2] eb 3f [2] fc 34 [2] e7 7a [2] da }

  condition:
    any of them
}