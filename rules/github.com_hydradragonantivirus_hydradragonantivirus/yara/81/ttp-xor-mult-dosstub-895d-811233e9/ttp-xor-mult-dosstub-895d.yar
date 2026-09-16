rule TTP_XOR_MULT_DOSStub_895d {
  strings:
    $key_895d = { dd 35 [2] a9 2d [2] ee 2f [2] a9 3e [2] e7 32 [2] eb 38 [2] fc 33 [2] e7 7d [2] da }

  condition:
    any of them
}