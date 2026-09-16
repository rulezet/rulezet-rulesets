rule TTP_XOR_MULT_DOSStub_ce64 {
  strings:
    $key_ce64 = { 9a 0c [2] ee 14 [2] a9 16 [2] ee 07 [2] a0 0b [2] ac 01 [2] bb 0a [2] a0 44 [2] 9d }

  condition:
    any of them
}