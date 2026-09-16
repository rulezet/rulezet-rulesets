rule TTP_XOR_MULT_DOSStub_1697 {
  strings:
    $key_1697 = { 42 ff [2] 36 e7 [2] 71 e5 [2] 36 f4 [2] 78 f8 [2] 74 f2 [2] 63 f9 [2] 78 b7 [2] 45 }

  condition:
    any of them
}