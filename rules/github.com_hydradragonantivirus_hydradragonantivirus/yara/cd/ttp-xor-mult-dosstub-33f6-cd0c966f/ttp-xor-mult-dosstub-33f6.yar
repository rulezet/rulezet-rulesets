rule TTP_XOR_MULT_DOSStub_33f6 {
  strings:
    $key_33f6 = { 67 9e [2] 13 86 [2] 54 84 [2] 13 95 [2] 5d 99 [2] 51 93 [2] 46 98 [2] 5d d6 [2] 60 }

  condition:
    any of them
}