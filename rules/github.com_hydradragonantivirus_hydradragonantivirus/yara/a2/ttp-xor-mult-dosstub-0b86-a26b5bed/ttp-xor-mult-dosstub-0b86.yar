rule TTP_XOR_MULT_DOSStub_0b86 {
  strings:
    $key_0b86 = { 5f ee [2] 2b f6 [2] 6c f4 [2] 2b e5 [2] 65 e9 [2] 69 e3 [2] 7e e8 [2] 65 a6 [2] 58 }

  condition:
    any of them
}