rule TTP_XOR_MULT_DOSStub_891b {
  strings:
    $key_891b = { dd 73 [2] a9 6b [2] ee 69 [2] a9 78 [2] e7 74 [2] eb 7e [2] fc 75 [2] e7 3b [2] da }

  condition:
    any of them
}