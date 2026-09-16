rule TTP_XOR_MULT_DOSStub_ce0f {
  strings:
    $key_ce0f = { 9a 67 [2] ee 7f [2] a9 7d [2] ee 6c [2] a0 60 [2] ac 6a [2] bb 61 [2] a0 2f [2] 9d }

  condition:
    any of them
}