rule TTP_XOR_MULT_DOSStub_5e87 {
  strings:
    $key_5e87 = { 0a ef [2] 7e f7 [2] 39 f5 [2] 7e e4 [2] 30 e8 [2] 3c e2 [2] 2b e9 [2] 30 a7 [2] 0d }

  condition:
    any of them
}