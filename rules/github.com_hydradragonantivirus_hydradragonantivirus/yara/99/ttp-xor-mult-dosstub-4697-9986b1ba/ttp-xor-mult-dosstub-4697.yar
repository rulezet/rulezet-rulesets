rule TTP_XOR_MULT_DOSStub_4697 {
  strings:
    $key_4697 = { 12 ff [2] 66 e7 [2] 21 e5 [2] 66 f4 [2] 28 f8 [2] 24 f2 [2] 33 f9 [2] 28 b7 [2] 15 }

  condition:
    any of them
}