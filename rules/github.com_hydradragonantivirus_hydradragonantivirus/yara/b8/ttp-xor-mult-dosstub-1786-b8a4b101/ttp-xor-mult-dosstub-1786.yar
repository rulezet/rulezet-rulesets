rule TTP_XOR_MULT_DOSStub_1786 {
  strings:
    $key_1786 = { 43 ee [2] 37 f6 [2] 70 f4 [2] 37 e5 [2] 79 e9 [2] 75 e3 [2] 62 e8 [2] 79 a6 [2] 44 }

  condition:
    any of them
}