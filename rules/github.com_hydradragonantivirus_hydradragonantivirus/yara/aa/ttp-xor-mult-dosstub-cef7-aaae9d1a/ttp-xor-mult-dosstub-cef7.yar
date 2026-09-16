rule TTP_XOR_MULT_DOSStub_cef7 {
  strings:
    $key_cef7 = { 9a 9f [2] ee 87 [2] a9 85 [2] ee 94 [2] a0 98 [2] ac 92 [2] bb 99 [2] a0 d7 [2] 9d }

  condition:
    any of them
}