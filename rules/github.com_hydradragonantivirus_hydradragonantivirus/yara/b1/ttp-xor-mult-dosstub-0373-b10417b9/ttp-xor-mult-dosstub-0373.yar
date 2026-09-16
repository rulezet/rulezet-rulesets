rule TTP_XOR_MULT_DOSStub_0373 {
  strings:
    $key_0373 = { 57 1b [2] 23 03 [2] 64 01 [2] 23 10 [2] 6d 1c [2] 61 16 [2] 76 1d [2] 6d 53 [2] 50 }

  condition:
    any of them
}