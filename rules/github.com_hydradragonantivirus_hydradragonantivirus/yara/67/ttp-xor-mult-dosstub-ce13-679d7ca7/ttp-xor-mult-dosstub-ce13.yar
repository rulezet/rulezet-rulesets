rule TTP_XOR_MULT_DOSStub_ce13 {
  strings:
    $key_ce13 = { 9a 7b [2] ee 63 [2] a9 61 [2] ee 70 [2] a0 7c [2] ac 76 [2] bb 7d [2] a0 33 [2] 9d }

  condition:
    any of them
}