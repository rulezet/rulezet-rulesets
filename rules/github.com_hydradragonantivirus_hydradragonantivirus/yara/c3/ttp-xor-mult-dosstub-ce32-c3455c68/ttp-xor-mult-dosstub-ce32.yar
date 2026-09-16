rule TTP_XOR_MULT_DOSStub_ce32 {
  strings:
    $key_ce32 = { 9a 5a [2] ee 42 [2] a9 40 [2] ee 51 [2] a0 5d [2] ac 57 [2] bb 5c [2] a0 12 [2] 9d }

  condition:
    any of them
}