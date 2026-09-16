rule TTP_XOR_MULT_DOSStub_31f3 {
  strings:
    $key_31f3 = { 65 9b [2] 11 83 [2] 56 81 [2] 11 90 [2] 5f 9c [2] 53 96 [2] 44 9d [2] 5f d3 [2] 62 }

  condition:
    any of them
}