rule TTP_XOR_MULT_DOSStub_ce4a {
  strings:
    $key_ce4a = { 9a 22 [2] ee 3a [2] a9 38 [2] ee 29 [2] a0 25 [2] ac 2f [2] bb 24 [2] a0 6a [2] 9d }

  condition:
    any of them
}