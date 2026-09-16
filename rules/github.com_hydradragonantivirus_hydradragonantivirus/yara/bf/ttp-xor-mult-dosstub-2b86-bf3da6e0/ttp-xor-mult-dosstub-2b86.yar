rule TTP_XOR_MULT_DOSStub_2b86 {
  strings:
    $key_2b86 = { 7f ee [2] 0b f6 [2] 4c f4 [2] 0b e5 [2] 45 e9 [2] 49 e3 [2] 5e e8 [2] 45 a6 [2] 78 }

  condition:
    any of them
}