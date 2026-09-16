rule TTP_XOR_MULT_DOSStub_1fc7 {
  strings:
    $key_1fc7 = { 4b af [2] 3f b7 [2] 78 b5 [2] 3f a4 [2] 71 a8 [2] 7d a2 [2] 6a a9 [2] 71 e7 [2] 4c }

  condition:
    any of them
}