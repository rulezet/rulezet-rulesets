rule TTP_XOR_MULT_DOSStub_22f3 {
  strings:
    $key_22f3 = { 76 9b [2] 02 83 [2] 45 81 [2] 02 90 [2] 4c 9c [2] 40 96 [2] 57 9d [2] 4c d3 [2] 71 }

  condition:
    any of them
}