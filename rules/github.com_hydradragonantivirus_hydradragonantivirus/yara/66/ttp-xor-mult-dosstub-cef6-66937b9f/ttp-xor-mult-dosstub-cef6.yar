rule TTP_XOR_MULT_DOSStub_cef6 {
  strings:
    $key_cef6 = { 9a 9e [2] ee 86 [2] a9 84 [2] ee 95 [2] a0 99 [2] ac 93 [2] bb 98 [2] a0 d6 [2] 9d }

  condition:
    any of them
}