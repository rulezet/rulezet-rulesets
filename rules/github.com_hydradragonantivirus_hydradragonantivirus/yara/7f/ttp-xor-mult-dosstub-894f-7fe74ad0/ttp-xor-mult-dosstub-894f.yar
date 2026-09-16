rule TTP_XOR_MULT_DOSStub_894f {
  strings:
    $key_894f = { dd 27 [2] a9 3f [2] ee 3d [2] a9 2c [2] e7 20 [2] eb 2a [2] fc 21 [2] e7 6f [2] da }

  condition:
    any of them
}