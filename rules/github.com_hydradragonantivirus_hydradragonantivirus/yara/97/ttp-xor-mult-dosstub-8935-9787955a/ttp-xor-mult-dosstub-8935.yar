rule TTP_XOR_MULT_DOSStub_8935 {
  strings:
    $key_8935 = { dd 5d [2] a9 45 [2] ee 47 [2] a9 56 [2] e7 5a [2] eb 50 [2] fc 5b [2] e7 15 [2] da }

  condition:
    any of them
}