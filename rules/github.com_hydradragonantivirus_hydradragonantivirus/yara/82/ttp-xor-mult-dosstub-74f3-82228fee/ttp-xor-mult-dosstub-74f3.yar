rule TTP_XOR_MULT_DOSStub_74f3 {
  strings:
    $key_74f3 = { 20 9b [2] 54 83 [2] 13 81 [2] 54 90 [2] 1a 9c [2] 16 96 [2] 01 9d [2] 1a d3 [2] 27 }

  condition:
    any of them
}