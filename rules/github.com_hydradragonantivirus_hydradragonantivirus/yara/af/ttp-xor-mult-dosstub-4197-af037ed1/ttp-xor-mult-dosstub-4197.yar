rule TTP_XOR_MULT_DOSStub_4197 {
  strings:
    $key_4197 = { 15 ff [2] 61 e7 [2] 26 e5 [2] 61 f4 [2] 2f f8 [2] 23 f2 [2] 34 f9 [2] 2f b7 [2] 12 }

  condition:
    any of them
}