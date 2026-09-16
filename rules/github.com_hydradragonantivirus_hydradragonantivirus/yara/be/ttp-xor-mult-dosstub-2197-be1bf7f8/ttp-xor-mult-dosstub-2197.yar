rule TTP_XOR_MULT_DOSStub_2197 {
  strings:
    $key_2197 = { 75 ff [2] 01 e7 [2] 46 e5 [2] 01 f4 [2] 4f f8 [2] 43 f2 [2] 54 f9 [2] 4f b7 [2] 72 }

  condition:
    any of them
}