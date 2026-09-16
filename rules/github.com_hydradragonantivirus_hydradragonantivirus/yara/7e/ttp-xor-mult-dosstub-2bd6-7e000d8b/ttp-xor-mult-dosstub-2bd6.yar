rule TTP_XOR_MULT_DOSStub_2bd6 {
  strings:
    $key_2bd6 = { 7f be [2] 0b a6 [2] 4c a4 [2] 0b b5 [2] 45 b9 [2] 49 b3 [2] 5e b8 [2] 45 f6 [2] 78 }

  condition:
    any of them
}