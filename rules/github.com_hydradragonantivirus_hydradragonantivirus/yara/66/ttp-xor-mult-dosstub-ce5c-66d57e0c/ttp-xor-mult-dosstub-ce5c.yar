rule TTP_XOR_MULT_DOSStub_ce5c {
  strings:
    $key_ce5c = { 9a 34 [2] ee 2c [2] a9 2e [2] ee 3f [2] a0 33 [2] ac 39 [2] bb 32 [2] a0 7c [2] 9d }

  condition:
    any of them
}