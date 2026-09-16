rule TTP_XOR_MULT_DOSStub_1354 {
  strings:
    $key_1354 = { 47 3c [2] 33 24 [2] 74 26 [2] 33 37 [2] 7d 3b [2] 71 31 [2] 66 3a [2] 7d 74 [2] 40 }

  condition:
    any of them
}