rule TTP_XOR_MULT_DOSStub_6b86 {
  strings:
    $key_6b86 = { 3f ee [2] 4b f6 [2] 0c f4 [2] 4b e5 [2] 05 e9 [2] 09 e3 [2] 1e e8 [2] 05 a6 [2] 38 }

  condition:
    any of them
}