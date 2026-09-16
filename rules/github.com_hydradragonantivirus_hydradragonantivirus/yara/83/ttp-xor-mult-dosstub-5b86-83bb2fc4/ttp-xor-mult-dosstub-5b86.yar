rule TTP_XOR_MULT_DOSStub_5b86 {
  strings:
    $key_5b86 = { 0f ee [2] 7b f6 [2] 3c f4 [2] 7b e5 [2] 35 e9 [2] 39 e3 [2] 2e e8 [2] 35 a6 [2] 08 }

  condition:
    any of them
}