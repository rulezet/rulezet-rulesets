rule TTP_XOR_MULT_DOSStub_7b87 {
  strings:
    $key_7b87 = { 2f ef [2] 5b f7 [2] 1c f5 [2] 5b e4 [2] 15 e8 [2] 19 e2 [2] 0e e9 [2] 15 a7 [2] 28 }

  condition:
    any of them
}