rule TTP_XOR_MULT_DOSStub_ce52 {
  strings:
    $key_ce52 = { 9a 3a [2] ee 22 [2] a9 20 [2] ee 31 [2] a0 3d [2] ac 37 [2] bb 3c [2] a0 72 [2] 9d }

  condition:
    any of them
}