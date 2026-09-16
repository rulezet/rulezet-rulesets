rule TTP_XOR_MULT_DOSStub_52c7 {
  strings:
    $key_52c7 = { 06 af [2] 72 b7 [2] 35 b5 [2] 72 a4 [2] 3c a8 [2] 30 a2 [2] 27 a9 [2] 3c e7 [2] 01 }

  condition:
    any of them
}