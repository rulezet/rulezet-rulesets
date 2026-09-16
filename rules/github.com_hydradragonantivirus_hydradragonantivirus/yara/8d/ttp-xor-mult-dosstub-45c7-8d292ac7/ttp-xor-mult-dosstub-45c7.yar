rule TTP_XOR_MULT_DOSStub_45c7 {
  strings:
    $key_45c7 = { 11 af [2] 65 b7 [2] 22 b5 [2] 65 a4 [2] 2b a8 [2] 27 a2 [2] 30 a9 [2] 2b e7 [2] 16 }

  condition:
    any of them
}