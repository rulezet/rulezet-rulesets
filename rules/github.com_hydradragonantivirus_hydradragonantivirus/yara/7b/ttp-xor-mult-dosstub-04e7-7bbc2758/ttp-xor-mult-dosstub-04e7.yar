rule TTP_XOR_MULT_DOSStub_04e7 {
  strings:
    $key_04e7 = { 50 8f [2] 24 97 [2] 63 95 [2] 24 84 [2] 6a 88 [2] 66 82 [2] 71 89 [2] 6a c7 [2] 57 }

  condition:
    any of them
}