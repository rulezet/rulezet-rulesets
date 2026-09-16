rule TTP_XOR_MULT_DOSStub_0347 {
  strings:
    $key_0347 = { 57 2f [2] 23 37 [2] 64 35 [2] 23 24 [2] 6d 28 [2] 61 22 [2] 76 29 [2] 6d 67 [2] 50 }

  condition:
    any of them
}