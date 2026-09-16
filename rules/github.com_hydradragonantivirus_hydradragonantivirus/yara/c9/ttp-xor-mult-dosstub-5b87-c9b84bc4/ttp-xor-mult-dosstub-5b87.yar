rule TTP_XOR_MULT_DOSStub_5b87 {
  strings:
    $key_5b87 = { 0f ef [2] 7b f7 [2] 3c f5 [2] 7b e4 [2] 35 e8 [2] 39 e2 [2] 2e e9 [2] 35 a7 [2] 08 }

  condition:
    any of them
}