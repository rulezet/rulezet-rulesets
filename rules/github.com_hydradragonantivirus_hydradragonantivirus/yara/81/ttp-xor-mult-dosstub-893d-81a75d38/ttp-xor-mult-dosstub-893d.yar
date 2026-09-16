rule TTP_XOR_MULT_DOSStub_893d {
  strings:
    $key_893d = { dd 55 [2] a9 4d [2] ee 4f [2] a9 5e [2] e7 52 [2] eb 58 [2] fc 53 [2] e7 1d [2] da }

  condition:
    any of them
}