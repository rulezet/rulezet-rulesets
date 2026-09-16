rule TTP_XOR_MULT_DOSStub_0097 {
  strings:
    $key_0097 = { 54 ff [2] 20 e7 [2] 67 e5 [2] 20 f4 [2] 6e f8 [2] 62 f2 [2] 75 f9 [2] 6e b7 [2] 53 }

  condition:
    any of them
}