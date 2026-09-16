rule TTP_XOR_MULT_DOSStub_ce29 {
  strings:
    $key_ce29 = { 9a 41 [2] ee 59 [2] a9 5b [2] ee 4a [2] a0 46 [2] ac 4c [2] bb 47 [2] a0 09 [2] 9d }

  condition:
    any of them
}