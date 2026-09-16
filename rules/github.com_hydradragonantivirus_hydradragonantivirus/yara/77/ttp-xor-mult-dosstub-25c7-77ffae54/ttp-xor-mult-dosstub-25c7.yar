rule TTP_XOR_MULT_DOSStub_25c7 {
  strings:
    $key_25c7 = { 71 af [2] 05 b7 [2] 42 b5 [2] 05 a4 [2] 4b a8 [2] 47 a2 [2] 50 a9 [2] 4b e7 [2] 76 }

  condition:
    any of them
}