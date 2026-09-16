rule TTP_XOR_MULT_DOSStub_7797 {
  strings:
    $key_7797 = { 23 ff [2] 57 e7 [2] 10 e5 [2] 57 f4 [2] 19 f8 [2] 15 f2 [2] 02 f9 [2] 19 b7 [2] 24 }

  condition:
    any of them
}