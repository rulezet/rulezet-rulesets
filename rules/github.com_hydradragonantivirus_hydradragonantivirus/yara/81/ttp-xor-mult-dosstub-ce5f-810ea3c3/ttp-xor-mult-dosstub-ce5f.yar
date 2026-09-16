rule TTP_XOR_MULT_DOSStub_ce5f {
  strings:
    $key_ce5f = { 9a 37 [2] ee 2f [2] a9 2d [2] ee 3c [2] a0 30 [2] ac 3a [2] bb 31 [2] a0 7f [2] 9d }

  condition:
    any of them
}