rule TTP_XOR_MULT_DOSStub_3b86 {
  strings:
    $key_3b86 = { 6f ee [2] 1b f6 [2] 5c f4 [2] 1b e5 [2] 55 e9 [2] 59 e3 [2] 4e e8 [2] 55 a6 [2] 68 }

  condition:
    any of them
}