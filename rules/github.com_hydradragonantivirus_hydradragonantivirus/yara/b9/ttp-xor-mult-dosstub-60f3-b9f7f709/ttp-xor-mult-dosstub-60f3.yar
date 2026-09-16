rule TTP_XOR_MULT_DOSStub_60f3 {
  strings:
    $key_60f3 = { 34 9b [2] 40 83 [2] 07 81 [2] 40 90 [2] 0e 9c [2] 02 96 [2] 15 9d [2] 0e d3 [2] 33 }

  condition:
    any of them
}