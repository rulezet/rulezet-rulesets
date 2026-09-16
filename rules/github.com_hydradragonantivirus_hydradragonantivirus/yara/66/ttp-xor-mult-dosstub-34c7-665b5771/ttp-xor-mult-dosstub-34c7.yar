rule TTP_XOR_MULT_DOSStub_34c7 {
  strings:
    $key_34c7 = { 60 af [2] 14 b7 [2] 53 b5 [2] 14 a4 [2] 5a a8 [2] 56 a2 [2] 41 a9 [2] 5a e7 [2] 67 }

  condition:
    any of them
}