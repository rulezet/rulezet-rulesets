rule TTP_XOR_MULT_DOSStub_3197 {
  strings:
    $key_3197 = { 65 ff [2] 11 e7 [2] 56 e5 [2] 11 f4 [2] 5f f8 [2] 53 f2 [2] 44 f9 [2] 5f b7 [2] 62 }

  condition:
    any of them
}