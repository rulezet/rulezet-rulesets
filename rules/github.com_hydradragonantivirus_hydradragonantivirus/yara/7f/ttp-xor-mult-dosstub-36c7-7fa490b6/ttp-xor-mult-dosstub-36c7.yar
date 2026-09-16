rule TTP_XOR_MULT_DOSStub_36c7 {
  strings:
    $key_36c7 = { 62 af [2] 16 b7 [2] 51 b5 [2] 16 a4 [2] 58 a8 [2] 54 a2 [2] 43 a9 [2] 58 e7 [2] 65 }

  condition:
    any of them
}