rule TTP_XOR_MULT_DOSStub_33f1 {
  strings:
    $key_33f1 = { 67 99 [2] 13 81 [2] 54 83 [2] 13 92 [2] 5d 9e [2] 51 94 [2] 46 9f [2] 5d d1 [2] 60 }

  condition:
    any of them
}