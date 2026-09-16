rule TTP_XOR_MULT_DOSStub_2186 {
  strings:
    $key_2186 = { 75 ee [2] 01 f6 [2] 46 f4 [2] 01 e5 [2] 4f e9 [2] 43 e3 [2] 54 e8 [2] 4f a6 [2] 72 }

  condition:
    any of them
}