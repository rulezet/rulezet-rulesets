rule TTP_XOR_MULT_DOSStub_ce4d {
  strings:
    $key_ce4d = { 9a 25 [2] ee 3d [2] a9 3f [2] ee 2e [2] a0 22 [2] ac 28 [2] bb 23 [2] a0 6d [2] 9d }

  condition:
    any of them
}