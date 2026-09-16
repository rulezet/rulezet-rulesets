rule TTP_XOR_MULT_DOSStub_e5c7 {
  strings:
    $key_e5c7 = { b1 af [2] c5 b7 [2] 82 b5 [2] c5 a4 [2] 8b a8 [2] 87 a2 [2] 90 a9 [2] 8b e7 [2] b6 }

  condition:
    any of them
}