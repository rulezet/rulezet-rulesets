rule TTP_XOR_MULT_DOSStub_54f3 {
  strings:
    $key_54f3 = { 00 9b [2] 74 83 [2] 33 81 [2] 74 90 [2] 3a 9c [2] 36 96 [2] 21 9d [2] 3a d3 [2] 07 }

  condition:
    any of them
}