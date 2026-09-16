rule TTP_XOR_MULT_DOSStub_0497 {
  strings:
    $key_0497 = { 50 ff [2] 24 e7 [2] 63 e5 [2] 24 f4 [2] 6a f8 [2] 66 f2 [2] 71 f9 [2] 6a b7 [2] 57 }

  condition:
    any of them
}