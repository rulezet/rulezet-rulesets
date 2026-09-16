rule TTP_XOR_MULT_DOSStub_26d6 {
  strings:
    $key_26d6 = { 72 be [2] 06 a6 [2] 41 a4 [2] 06 b5 [2] 48 b9 [2] 44 b3 [2] 53 b8 [2] 48 f6 [2] 75 }

  condition:
    any of them
}