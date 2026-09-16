rule TTP_XOR_MULT_DOSStub_65c1 {
  strings:
    $key_65c1 = { 31 a9 [2] 45 b1 [2] 02 b3 [2] 45 a2 [2] 0b ae [2] 07 a4 [2] 10 af [2] 0b e1 [2] 36 }

  condition:
    any of them
}