rule TTP_XOR_MULT_DOSStub_27c7 {
  strings:
    $key_27c7 = { 73 af [2] 07 b7 [2] 40 b5 [2] 07 a4 [2] 49 a8 [2] 45 a2 [2] 52 a9 [2] 49 e7 [2] 74 }

  condition:
    any of them
}