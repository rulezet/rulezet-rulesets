rule TTP_XOR_MULT_DOSStub_2af3 {
  strings:
    $key_2af3 = { 7e 9b [2] 0a 83 [2] 4d 81 [2] 0a 90 [2] 44 9c [2] 48 96 [2] 5f 9d [2] 44 d3 [2] 79 }

  condition:
    any of them
}