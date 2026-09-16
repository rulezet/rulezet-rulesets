rule TTP_XOR_MULT_DOSStub_3b87 {
  strings:
    $key_3b87 = { 6f ef [2] 1b f7 [2] 5c f5 [2] 1b e4 [2] 55 e8 [2] 59 e2 [2] 4e e9 [2] 55 a7 [2] 68 }

  condition:
    any of them
}