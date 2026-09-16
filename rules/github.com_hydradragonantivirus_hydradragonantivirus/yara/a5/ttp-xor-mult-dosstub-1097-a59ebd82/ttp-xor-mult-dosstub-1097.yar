rule TTP_XOR_MULT_DOSStub_1097 {
  strings:
    $key_1097 = { 44 ff [2] 30 e7 [2] 77 e5 [2] 30 f4 [2] 7e f8 [2] 72 f2 [2] 65 f9 [2] 7e b7 [2] 43 }

  condition:
    any of them
}