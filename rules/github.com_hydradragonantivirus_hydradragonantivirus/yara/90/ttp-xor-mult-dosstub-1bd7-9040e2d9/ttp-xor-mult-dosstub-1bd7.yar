rule TTP_XOR_MULT_DOSStub_1bd7 {
  strings:
    $key_1bd7 = { 4f bf [2] 3b a7 [2] 7c a5 [2] 3b b4 [2] 75 b8 [2] 79 b2 [2] 6e b9 [2] 75 f7 [2] 48 }

  condition:
    any of them
}