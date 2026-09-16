rule TTP_XOR_MULT_DOSStub_7bd7 {
  strings:
    $key_7bd7 = { 2f bf [2] 5b a7 [2] 1c a5 [2] 5b b4 [2] 15 b8 [2] 19 b2 [2] 0e b9 [2] 15 f7 [2] 28 }

  condition:
    any of them
}