rule TTP_XOR_MULT_DOSStub_caf3 {
  strings:
    $key_caf3 = { 9e 9b [2] ea 83 [2] ad 81 [2] ea 90 [2] a4 9c [2] a8 96 [2] bf 9d [2] a4 d3 [2] 99 }

  condition:
    any of them
}