rule TTP_XOR_MULT_DOSStub_ce03 {
  strings:
    $key_ce03 = { 9a 6b [2] ee 73 [2] a9 71 [2] ee 60 [2] a0 6c [2] ac 66 [2] bb 6d [2] a0 23 [2] 9d }

  condition:
    any of them
}