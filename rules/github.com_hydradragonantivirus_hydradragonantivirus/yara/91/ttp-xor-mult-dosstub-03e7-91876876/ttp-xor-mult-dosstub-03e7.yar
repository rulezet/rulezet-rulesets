rule TTP_XOR_MULT_DOSStub_03e7 {
  strings:
    $key_03e7 = { 57 8f [2] 23 97 [2] 64 95 [2] 23 84 [2] 6d 88 [2] 61 82 [2] 76 89 [2] 6d c7 [2] 50 }

  condition:
    any of them
}