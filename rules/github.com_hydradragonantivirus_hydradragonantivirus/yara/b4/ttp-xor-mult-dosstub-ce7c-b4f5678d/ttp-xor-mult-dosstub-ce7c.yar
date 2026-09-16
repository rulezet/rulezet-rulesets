rule TTP_XOR_MULT_DOSStub_ce7c {
  strings:
    $key_ce7c = { 9a 14 [2] ee 0c [2] a9 0e [2] ee 1f [2] a0 13 [2] ac 19 [2] bb 12 [2] a0 5c [2] 9d }

  condition:
    any of them
}