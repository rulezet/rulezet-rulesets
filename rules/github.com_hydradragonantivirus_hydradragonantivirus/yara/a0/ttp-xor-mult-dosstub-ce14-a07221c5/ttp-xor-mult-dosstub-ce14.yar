rule TTP_XOR_MULT_DOSStub_ce14 {
  strings:
    $key_ce14 = { 9a 7c [2] ee 64 [2] a9 66 [2] ee 77 [2] a0 7b [2] ac 71 [2] bb 7a [2] a0 34 [2] 9d }

  condition:
    any of them
}