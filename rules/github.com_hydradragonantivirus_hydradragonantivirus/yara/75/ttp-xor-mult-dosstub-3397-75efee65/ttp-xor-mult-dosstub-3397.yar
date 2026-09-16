rule TTP_XOR_MULT_DOSStub_3397 {
  strings:
    $key_3397 = { 67 ff [2] 13 e7 [2] 54 e5 [2] 13 f4 [2] 5d f8 [2] 51 f2 [2] 46 f9 [2] 5d b7 [2] 60 }

  condition:
    any of them
}