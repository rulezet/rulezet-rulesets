rule TTP_XOR_MULT_DOSStub_58f3 {
  strings:
    $key_58f3 = { 0c 9b [2] 78 83 [2] 3f 81 [2] 78 90 [2] 36 9c [2] 3a 96 [2] 2d 9d [2] 36 d3 [2] 0b }

  condition:
    any of them
}