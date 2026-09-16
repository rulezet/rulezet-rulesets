rule TTP_XOR_MULT_DOSStub_8912 {
  strings:
    $key_8912 = { dd 7a [2] a9 62 [2] ee 60 [2] a9 71 [2] e7 7d [2] eb 77 [2] fc 7c [2] e7 32 [2] da }

  condition:
    any of them
}