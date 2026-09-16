rule TTP_XOR_MULT_DOSStub_03f3 {
  strings:
    $key_03f3 = { 57 9b [2] 23 83 [2] 64 81 [2] 23 90 [2] 6d 9c [2] 61 96 [2] 76 9d [2] 6d d3 [2] 50 }

  condition:
    any of them
}