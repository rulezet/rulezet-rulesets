rule TTP_XOR_MULT_DOSStub_ce62 {
  strings:
    $key_ce62 = { 9a 0a [2] ee 12 [2] a9 10 [2] ee 01 [2] a0 0d [2] ac 07 [2] bb 0c [2] a0 42 [2] 9d }

  condition:
    any of them
}