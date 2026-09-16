rule TTP_XOR_MULT_DOSStub_890b {
  strings:
    $key_890b = { dd 63 [2] a9 7b [2] ee 79 [2] a9 68 [2] e7 64 [2] eb 6e [2] fc 65 [2] e7 2b [2] da }

  condition:
    any of them
}