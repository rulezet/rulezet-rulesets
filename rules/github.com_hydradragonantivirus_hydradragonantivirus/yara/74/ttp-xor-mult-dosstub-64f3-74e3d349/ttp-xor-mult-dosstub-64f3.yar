rule TTP_XOR_MULT_DOSStub_64f3 {
  strings:
    $key_64f3 = { 30 9b [2] 44 83 [2] 03 81 [2] 44 90 [2] 0a 9c [2] 06 96 [2] 11 9d [2] 0a d3 [2] 37 }

  condition:
    any of them
}