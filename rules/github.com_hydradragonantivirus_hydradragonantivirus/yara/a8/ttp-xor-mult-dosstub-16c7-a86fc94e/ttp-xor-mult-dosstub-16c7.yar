rule TTP_XOR_MULT_DOSStub_16c7 {
  strings:
    $key_16c7 = { 42 af [2] 36 b7 [2] 71 b5 [2] 36 a4 [2] 78 a8 [2] 74 a2 [2] 63 a9 [2] 78 e7 [2] 45 }

  condition:
    any of them
}