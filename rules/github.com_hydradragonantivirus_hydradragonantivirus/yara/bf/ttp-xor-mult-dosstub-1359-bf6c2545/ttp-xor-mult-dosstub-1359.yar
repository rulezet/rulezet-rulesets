rule TTP_XOR_MULT_DOSStub_1359 {
  strings:
    $key_1359 = { 47 31 [2] 33 29 [2] 74 2b [2] 33 3a [2] 7d 36 [2] 71 3c [2] 66 37 [2] 7d 79 [2] 40 }

  condition:
    any of them
}