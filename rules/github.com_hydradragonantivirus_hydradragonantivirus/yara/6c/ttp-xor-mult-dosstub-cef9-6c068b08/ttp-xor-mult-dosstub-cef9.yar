rule TTP_XOR_MULT_DOSStub_cef9 {
  strings:
    $key_cef9 = { 9a 91 [2] ee 89 [2] a9 8b [2] ee 9a [2] a0 96 [2] ac 9c [2] bb 97 [2] a0 d9 [2] 9d }

  condition:
    any of them
}