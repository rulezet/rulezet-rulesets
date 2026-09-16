rule TTP_XOR_MULT_DOSStub_ce59 {
  strings:
    $key_ce59 = { 9a 31 [2] ee 29 [2] a9 2b [2] ee 3a [2] a0 36 [2] ac 3c [2] bb 37 [2] a0 79 [2] 9d }

  condition:
    any of them
}