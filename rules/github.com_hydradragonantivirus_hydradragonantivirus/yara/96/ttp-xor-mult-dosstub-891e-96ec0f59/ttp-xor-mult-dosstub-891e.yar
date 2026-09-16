rule TTP_XOR_MULT_DOSStub_891e {
  strings:
    $key_891e = { dd 76 [2] a9 6e [2] ee 6c [2] a9 7d [2] e7 71 [2] eb 7b [2] fc 70 [2] e7 3e [2] da }

  condition:
    any of them
}