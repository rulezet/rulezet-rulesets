rule TTP_XOR_MULT_DOSStub_40f3 {
  strings:
    $key_40f3 = { 14 9b [2] 60 83 [2] 27 81 [2] 60 90 [2] 2e 9c [2] 22 96 [2] 35 9d [2] 2e d3 [2] 13 }

  condition:
    any of them
}