rule TTP_XOR_MULT_DOSStub_0397 {
  strings:
    $key_0397 = { 57 ff [2] 23 e7 [2] 64 e5 [2] 23 f4 [2] 6d f8 [2] 61 f2 [2] 76 f9 [2] 6d b7 [2] 50 }

  condition:
    any of them
}