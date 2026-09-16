rule TTP_XOR_MULT_DOSStub_33f5 {
  strings:
    $key_33f5 = { 67 9d [2] 13 85 [2] 54 87 [2] 13 96 [2] 5d 9a [2] 51 90 [2] 46 9b [2] 5d d5 [2] 60 }

  condition:
    any of them
}