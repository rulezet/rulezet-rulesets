rule TTP_XOR_MULT_DOSStub_13c7 {
  strings:
    $key_13c7 = { 47 af [2] 33 b7 [2] 74 b5 [2] 33 a4 [2] 7d a8 [2] 71 a2 [2] 66 a9 [2] 7d e7 [2] 40 }

  condition:
    any of them
}