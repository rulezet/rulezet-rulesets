rule TTP_XOR_MULT_DOSStub_3bd7 {
  strings:
    $key_3bd7 = { 6f bf [2] 1b a7 [2] 5c a5 [2] 1b b4 [2] 55 b8 [2] 59 b2 [2] 4e b9 [2] 55 f7 [2] 68 }

  condition:
    any of them
}