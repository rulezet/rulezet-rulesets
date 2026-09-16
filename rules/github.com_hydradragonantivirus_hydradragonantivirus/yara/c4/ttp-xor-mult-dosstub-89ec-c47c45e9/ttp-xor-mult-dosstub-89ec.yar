rule TTP_XOR_MULT_DOSStub_89ec {
  strings:
    $key_89ec = { dd 84 [2] a9 9c [2] ee 9e [2] a9 8f [2] e7 83 [2] eb 89 [2] fc 82 [2] e7 cc [2] da }

  condition:
    any of them
}