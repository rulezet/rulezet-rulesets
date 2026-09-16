rule TTP_XOR_MULT_DOSStub_4af3 {
  strings:
    $key_4af3 = { 1e 9b [2] 6a 83 [2] 2d 81 [2] 6a 90 [2] 24 9c [2] 28 96 [2] 3f 9d [2] 24 d3 [2] 19 }

  condition:
    any of them
}