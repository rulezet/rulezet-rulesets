rule TTP_XOR_MULT_DOSStub_ce6f {
  strings:
    $key_ce6f = { 9a 07 [2] ee 1f [2] a9 1d [2] ee 0c [2] a0 00 [2] ac 0a [2] bb 01 [2] a0 4f [2] 9d }

  condition:
    any of them
}