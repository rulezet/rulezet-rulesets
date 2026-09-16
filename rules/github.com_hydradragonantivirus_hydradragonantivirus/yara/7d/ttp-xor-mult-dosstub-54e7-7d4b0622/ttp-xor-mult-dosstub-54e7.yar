rule TTP_XOR_MULT_DOSStub_54e7 {
  strings:
    $key_54e7 = { 00 8f [2] 74 97 [2] 33 95 [2] 74 84 [2] 3a 88 [2] 36 82 [2] 21 89 [2] 3a c7 [2] 07 }

  condition:
    any of them
}