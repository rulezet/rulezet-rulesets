rule TTP_XOR_MULT_DOSStub_2bd7 {
  strings:
    $key_2bd7 = { 7f bf [2] 0b a7 [2] 4c a5 [2] 0b b4 [2] 45 b8 [2] 49 b2 [2] 5e b9 [2] 45 f7 [2] 78 }

  condition:
    any of them
}