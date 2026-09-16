rule TTP_XOR_MULT_DOSStub_cef8 {
  strings:
    $key_cef8 = { 9a 90 [2] ee 88 [2] a9 8a [2] ee 9b [2] a0 97 [2] ac 9d [2] bb 96 [2] a0 d8 [2] 9d }

  condition:
    any of them
}