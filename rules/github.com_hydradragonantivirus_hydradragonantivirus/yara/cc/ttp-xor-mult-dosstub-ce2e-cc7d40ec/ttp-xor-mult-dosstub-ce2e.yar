rule TTP_XOR_MULT_DOSStub_ce2e {
  strings:
    $key_ce2e = { 9a 46 [2] ee 5e [2] a9 5c [2] ee 4d [2] a0 41 [2] ac 4b [2] bb 40 [2] a0 0e [2] 9d }

  condition:
    any of them
}