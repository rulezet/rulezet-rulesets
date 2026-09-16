rule TTP_XOR_MULT_DOSStub_1797 {
  strings:
    $key_1797 = { 43 ff [2] 37 e7 [2] 70 e5 [2] 37 f4 [2] 79 f8 [2] 75 f2 [2] 62 f9 [2] 79 b7 [2] 44 }

  condition:
    any of them
}