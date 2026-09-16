rule TTP_XOR_MULT_DOSStub_ce4c {
  strings:
    $key_ce4c = { 9a 24 [2] ee 3c [2] a9 3e [2] ee 2f [2] a0 23 [2] ac 29 [2] bb 22 [2] a0 6c [2] 9d }

  condition:
    any of them
}