rule TTP_XOR_MULT_DOSStub_2b87 {
  strings:
    $key_2b87 = { 7f ef [2] 0b f7 [2] 4c f5 [2] 0b e4 [2] 45 e8 [2] 49 e2 [2] 5e e9 [2] 45 a7 [2] 78 }

  condition:
    any of them
}