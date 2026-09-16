rule TTP_XOR_MULT_DOSStub_26c7 {
  strings:
    $key_26c7 = { 72 af [2] 06 b7 [2] 41 b5 [2] 06 a4 [2] 48 a8 [2] 44 a2 [2] 53 a9 [2] 48 e7 [2] 75 }

  condition:
    any of them
}