rule TTP_XOR_MULT_DOSStub_16c1 {
  strings:
    $key_16c1 = { 42 a9 [2] 36 b1 [2] 71 b3 [2] 36 a2 [2] 78 ae [2] 74 a4 [2] 63 af [2] 78 e1 [2] 45 }

  condition:
    any of them
}