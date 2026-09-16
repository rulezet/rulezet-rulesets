rule TTP_XOR_MULT_DOSStub_ce7f {
  strings:
    $key_ce7f = { 9a 17 [2] ee 0f [2] a9 0d [2] ee 1c [2] a0 10 [2] ac 1a [2] bb 11 [2] a0 5f [2] 9d }

  condition:
    any of them
}