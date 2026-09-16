rule TTP_XOR_MULT_DOSStub_cee9 {
  strings:
    $key_cee9 = { 9a 81 [2] ee 99 [2] a9 9b [2] ee 8a [2] a0 86 [2] ac 8c [2] bb 87 [2] a0 c9 [2] 9d }

  condition:
    any of them
}