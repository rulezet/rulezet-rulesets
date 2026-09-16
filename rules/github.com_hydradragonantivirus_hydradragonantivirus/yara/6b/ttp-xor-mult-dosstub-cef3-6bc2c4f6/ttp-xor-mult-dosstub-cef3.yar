rule TTP_XOR_MULT_DOSStub_cef3 {
  strings:
    $key_cef3 = { 9a 9b [2] ee 83 [2] a9 81 [2] ee 90 [2] a0 9c [2] ac 96 [2] bb 9d [2] a0 d3 [2] 9d }

  condition:
    any of them
}