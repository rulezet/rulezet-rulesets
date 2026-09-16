rule TTP_XOR_MULT_DOSStub_ce7e {
  strings:
    $key_ce7e = { 9a 16 [2] ee 0e [2] a9 0c [2] ee 1d [2] a0 11 [2] ac 1b [2] bb 10 [2] a0 5e [2] 9d }

  condition:
    any of them
}