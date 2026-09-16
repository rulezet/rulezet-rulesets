rule TTP_XOR_MULT_DOSStub_2097 {
  strings:
    $key_2097 = { 74 ff [2] 00 e7 [2] 47 e5 [2] 00 f4 [2] 4e f8 [2] 42 f2 [2] 55 f9 [2] 4e b7 [2] 73 }

  condition:
    any of them
}