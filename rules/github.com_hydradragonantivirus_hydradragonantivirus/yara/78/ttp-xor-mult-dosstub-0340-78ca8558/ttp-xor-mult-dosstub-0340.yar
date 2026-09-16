rule TTP_XOR_MULT_DOSStub_0340 {
  strings:
    $key_0340 = { 57 28 [2] 23 30 [2] 64 32 [2] 23 23 [2] 6d 2f [2] 61 25 [2] 76 2e [2] 6d 60 [2] 50 }

  condition:
    any of them
}