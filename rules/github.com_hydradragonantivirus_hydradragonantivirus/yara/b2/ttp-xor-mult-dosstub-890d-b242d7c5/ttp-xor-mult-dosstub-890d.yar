rule TTP_XOR_MULT_DOSStub_890d {
  strings:
    $key_890d = { dd 65 [2] a9 7d [2] ee 7f [2] a9 6e [2] e7 62 [2] eb 68 [2] fc 63 [2] e7 2d [2] da }

  condition:
    any of them
}