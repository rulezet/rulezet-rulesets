rule TTP_XOR_MULT_DOSStub_ce5e {
  strings:
    $key_ce5e = { 9a 36 [2] ee 2e [2] a9 2c [2] ee 3d [2] a0 31 [2] ac 3b [2] bb 30 [2] a0 7e [2] 9d }

  condition:
    any of them
}