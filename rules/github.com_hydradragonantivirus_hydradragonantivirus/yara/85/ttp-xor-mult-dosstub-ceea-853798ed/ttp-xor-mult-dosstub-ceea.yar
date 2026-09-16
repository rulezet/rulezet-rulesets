rule TTP_XOR_MULT_DOSStub_ceea {
  strings:
    $key_ceea = { 9a 82 [2] ee 9a [2] a9 98 [2] ee 89 [2] a0 85 [2] ac 8f [2] bb 84 [2] a0 ca [2] 9d }

  condition:
    any of them
}