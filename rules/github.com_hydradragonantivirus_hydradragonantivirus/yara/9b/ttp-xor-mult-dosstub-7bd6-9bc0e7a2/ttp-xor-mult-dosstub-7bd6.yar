rule TTP_XOR_MULT_DOSStub_7bd6 {
  strings:
    $key_7bd6 = { 2f be [2] 5b a6 [2] 1c a4 [2] 5b b5 [2] 15 b9 [2] 19 b3 [2] 0e b8 [2] 15 f6 [2] 28 }

  condition:
    any of them
}