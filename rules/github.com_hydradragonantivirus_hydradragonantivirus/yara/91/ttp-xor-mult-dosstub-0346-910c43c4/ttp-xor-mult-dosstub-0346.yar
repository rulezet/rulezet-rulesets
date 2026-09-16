rule TTP_XOR_MULT_DOSStub_0346 {
  strings:
    $key_0346 = { 57 2e [2] 23 36 [2] 64 34 [2] 23 25 [2] 6d 29 [2] 61 23 [2] 76 28 [2] 6d 66 [2] 50 }

  condition:
    any of them
}