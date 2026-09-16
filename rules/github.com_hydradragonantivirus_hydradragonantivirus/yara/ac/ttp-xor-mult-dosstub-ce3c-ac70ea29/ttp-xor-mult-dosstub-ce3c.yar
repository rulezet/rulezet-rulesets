rule TTP_XOR_MULT_DOSStub_ce3c {
  strings:
    $key_ce3c = { 9a 54 [2] ee 4c [2] a9 4e [2] ee 5f [2] a0 53 [2] ac 59 [2] bb 52 [2] a0 1c [2] 9d }

  condition:
    any of them
}