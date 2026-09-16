rule TTP_XOR_MULT_DOSStub_1af3 {
  strings:
    $key_1af3 = { 4e 9b [2] 3a 83 [2] 7d 81 [2] 3a 90 [2] 74 9c [2] 78 96 [2] 6f 9d [2] 74 d3 [2] 49 }

  condition:
    any of them
}