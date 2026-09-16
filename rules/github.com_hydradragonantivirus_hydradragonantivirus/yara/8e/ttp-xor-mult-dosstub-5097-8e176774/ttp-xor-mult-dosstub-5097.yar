rule TTP_XOR_MULT_DOSStub_5097 {
  strings:
    $key_5097 = { 04 ff [2] 70 e7 [2] 37 e5 [2] 70 f4 [2] 3e f8 [2] 32 f2 [2] 25 f9 [2] 3e b7 [2] 03 }

  condition:
    any of them
}