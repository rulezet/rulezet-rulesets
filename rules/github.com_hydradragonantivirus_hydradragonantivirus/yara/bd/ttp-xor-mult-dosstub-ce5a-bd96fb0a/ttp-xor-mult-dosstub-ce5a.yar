rule TTP_XOR_MULT_DOSStub_ce5a {
  strings:
    $key_ce5a = { 9a 32 [2] ee 2a [2] a9 28 [2] ee 39 [2] a0 35 [2] ac 3f [2] bb 34 [2] a0 7a [2] 9d }

  condition:
    any of them
}