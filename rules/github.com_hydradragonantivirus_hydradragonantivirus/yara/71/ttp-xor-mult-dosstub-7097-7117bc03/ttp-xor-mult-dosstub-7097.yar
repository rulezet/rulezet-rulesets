rule TTP_XOR_MULT_DOSStub_7097 {
  strings:
    $key_7097 = { 24 ff [2] 50 e7 [2] 17 e5 [2] 50 f4 [2] 1e f8 [2] 12 f2 [2] 05 f9 [2] 1e b7 [2] 23 }

  condition:
    any of them
}