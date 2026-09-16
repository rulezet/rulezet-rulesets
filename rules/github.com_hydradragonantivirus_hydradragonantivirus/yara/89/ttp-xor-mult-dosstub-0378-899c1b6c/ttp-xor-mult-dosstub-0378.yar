rule TTP_XOR_MULT_DOSStub_0378 {
  strings:
    $key_0378 = { 57 10 [2] 23 08 [2] 64 0a [2] 23 1b [2] 6d 17 [2] 61 1d [2] 76 16 [2] 6d 58 [2] 50 }

  condition:
    any of them
}