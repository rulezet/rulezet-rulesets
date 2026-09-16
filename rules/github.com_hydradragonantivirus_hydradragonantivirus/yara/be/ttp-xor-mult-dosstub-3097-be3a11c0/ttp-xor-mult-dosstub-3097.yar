rule TTP_XOR_MULT_DOSStub_3097 {
  strings:
    $key_3097 = { 64 ff [2] 10 e7 [2] 57 e5 [2] 10 f4 [2] 5e f8 [2] 52 f2 [2] 45 f9 [2] 5e b7 [2] 63 }

  condition:
    any of them
}