rule TTP_XOR_MULT_DOSStub_00f3 {
  strings:
    $key_00f3 = { 54 9b [2] 20 83 [2] 67 81 [2] 20 90 [2] 6e 9c [2] 62 96 [2] 75 9d [2] 6e d3 [2] 53 }

  condition:
    any of them
}