rule TTP_XOR_MULT_DOSStub_ce22 {
  strings:
    $key_ce22 = { 9a 4a [2] ee 52 [2] a9 50 [2] ee 41 [2] a0 4d [2] ac 47 [2] bb 4c [2] a0 02 [2] 9d }

  condition:
    any of them
}