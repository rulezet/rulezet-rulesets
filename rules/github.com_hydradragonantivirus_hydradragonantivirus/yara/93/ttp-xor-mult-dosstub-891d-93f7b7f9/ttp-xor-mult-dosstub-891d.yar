rule TTP_XOR_MULT_DOSStub_891d {
  strings:
    $key_891d = { dd 75 [2] a9 6d [2] ee 6f [2] a9 7e [2] e7 72 [2] eb 78 [2] fc 73 [2] e7 3d [2] da }

  condition:
    any of them
}