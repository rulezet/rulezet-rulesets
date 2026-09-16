rule TTP_XOR_MULT_DOSStub_3386 {
  strings:
    $key_3386 = { 67 ee [2] 13 f6 [2] 54 f4 [2] 13 e5 [2] 5d e9 [2] 51 e3 [2] 46 e8 [2] 5d a6 [2] 60 }

  condition:
    any of them
}