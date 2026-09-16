rule TTP_XOR_MULT_DOSStub_7697 {
  strings:
    $key_7697 = { 22 ff [2] 56 e7 [2] 11 e5 [2] 56 f4 [2] 18 f8 [2] 14 f2 [2] 03 f9 [2] 18 b7 [2] 25 }

  condition:
    any of them
}