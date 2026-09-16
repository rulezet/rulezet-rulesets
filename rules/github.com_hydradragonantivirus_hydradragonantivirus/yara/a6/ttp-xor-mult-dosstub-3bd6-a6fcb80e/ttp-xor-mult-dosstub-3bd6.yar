rule TTP_XOR_MULT_DOSStub_3bd6 {
  strings:
    $key_3bd6 = { 6f be [2] 1b a6 [2] 5c a4 [2] 1b b5 [2] 55 b9 [2] 59 b3 [2] 4e b8 [2] 55 f6 [2] 68 }

  condition:
    any of them
}