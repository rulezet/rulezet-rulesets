rule TTP_XOR_MULT_DOSStub_8929 {
  strings:
    $key_8929 = { dd 41 [2] a9 59 [2] ee 5b [2] a9 4a [2] e7 46 [2] eb 4c [2] fc 47 [2] e7 09 [2] da }

  condition:
    any of them
}