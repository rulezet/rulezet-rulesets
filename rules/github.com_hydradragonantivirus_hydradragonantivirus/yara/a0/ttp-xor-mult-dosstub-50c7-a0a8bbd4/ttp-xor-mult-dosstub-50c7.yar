rule TTP_XOR_MULT_DOSStub_50c7 {
  strings:
    $key_50c7 = { 04 af [2] 70 b7 [2] 37 b5 [2] 70 a4 [2] 3e a8 [2] 32 a2 [2] 25 a9 [2] 3e e7 [2] 03 }

  condition:
    any of them
}