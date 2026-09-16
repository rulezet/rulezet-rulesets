rule TTP_XOR_MULT_DOSStub_32f3 {
  strings:
    $key_32f3 = { 66 9b [2] 12 83 [2] 55 81 [2] 12 90 [2] 5c 9c [2] 50 96 [2] 47 9d [2] 5c d3 [2] 61 }

  condition:
    any of them
}