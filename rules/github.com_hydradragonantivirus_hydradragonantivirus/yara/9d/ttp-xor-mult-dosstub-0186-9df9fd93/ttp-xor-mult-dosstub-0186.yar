rule TTP_XOR_MULT_DOSStub_0186 {
  strings:
    $key_0186 = { 55 ee [2] 21 f6 [2] 66 f4 [2] 21 e5 [2] 6f e9 [2] 63 e3 [2] 74 e8 [2] 6f a6 [2] 52 }

  condition:
    any of them
}