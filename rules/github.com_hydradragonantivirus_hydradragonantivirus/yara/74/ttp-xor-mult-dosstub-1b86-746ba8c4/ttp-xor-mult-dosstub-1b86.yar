rule TTP_XOR_MULT_DOSStub_1b86 {
  strings:
    $key_1b86 = { 4f ee [2] 3b f6 [2] 7c f4 [2] 3b e5 [2] 75 e9 [2] 79 e3 [2] 6e e8 [2] 75 a6 [2] 48 }

  condition:
    any of them
}