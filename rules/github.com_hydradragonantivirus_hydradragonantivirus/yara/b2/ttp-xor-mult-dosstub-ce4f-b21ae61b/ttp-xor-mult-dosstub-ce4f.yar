rule TTP_XOR_MULT_DOSStub_ce4f {
  strings:
    $key_ce4f = { 9a 27 [2] ee 3f [2] a9 3d [2] ee 2c [2] a0 20 [2] ac 2a [2] bb 21 [2] a0 6f [2] 9d }

  condition:
    any of them
}