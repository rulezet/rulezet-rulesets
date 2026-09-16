rule TTP_XOR_MULT_DOSStub_895e {
  strings:
    $key_895e = { dd 36 [2] a9 2e [2] ee 2c [2] a9 3d [2] e7 31 [2] eb 3b [2] fc 30 [2] e7 7e [2] da }

  condition:
    any of them
}