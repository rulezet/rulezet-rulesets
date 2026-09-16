rule TTP_XOR_MULT_DOSStub_5bd7 {
  strings:
    $key_5bd7 = { 0f bf [2] 7b a7 [2] 3c a5 [2] 7b b4 [2] 35 b8 [2] 39 b2 [2] 2e b9 [2] 35 f7 [2] 08 }

  condition:
    any of them
}