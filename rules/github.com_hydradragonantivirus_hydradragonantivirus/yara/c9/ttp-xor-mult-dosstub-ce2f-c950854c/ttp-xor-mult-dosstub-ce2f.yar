rule TTP_XOR_MULT_DOSStub_ce2f {
  strings:
    $key_ce2f = { 9a 47 [2] ee 5f [2] a9 5d [2] ee 4c [2] a0 40 [2] ac 4a [2] bb 41 [2] a0 0f [2] 9d }

  condition:
    any of them
}