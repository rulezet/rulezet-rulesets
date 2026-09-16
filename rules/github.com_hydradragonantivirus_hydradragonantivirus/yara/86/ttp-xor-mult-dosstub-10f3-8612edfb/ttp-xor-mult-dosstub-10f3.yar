rule TTP_XOR_MULT_DOSStub_10f3 {
  strings:
    $key_10f3 = { 44 9b [2] 30 83 [2] 77 81 [2] 30 90 [2] 7e 9c [2] 72 96 [2] 65 9d [2] 7e d3 [2] 43 }

  condition:
    any of them
}