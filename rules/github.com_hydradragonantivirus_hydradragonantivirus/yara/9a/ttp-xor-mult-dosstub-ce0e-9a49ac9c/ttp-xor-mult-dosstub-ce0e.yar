rule TTP_XOR_MULT_DOSStub_ce0e {
  strings:
    $key_ce0e = { 9a 66 [2] ee 7e [2] a9 7c [2] ee 6d [2] a0 61 [2] ac 6b [2] bb 60 [2] a0 2e [2] 9d }

  condition:
    any of them
}