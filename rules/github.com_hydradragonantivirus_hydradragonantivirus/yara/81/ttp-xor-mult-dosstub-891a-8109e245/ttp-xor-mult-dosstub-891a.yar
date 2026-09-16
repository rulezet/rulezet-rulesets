rule TTP_XOR_MULT_DOSStub_891a {
  strings:
    $key_891a = { dd 72 [2] a9 6a [2] ee 68 [2] a9 79 [2] e7 75 [2] eb 7f [2] fc 74 [2] e7 3a [2] da }

  condition:
    any of them
}