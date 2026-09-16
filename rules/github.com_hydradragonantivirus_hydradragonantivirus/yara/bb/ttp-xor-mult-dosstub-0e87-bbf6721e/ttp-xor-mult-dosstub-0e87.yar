rule TTP_XOR_MULT_DOSStub_0e87 {
  strings:
    $key_0e87 = { 5a ef [2] 2e f7 [2] 69 f5 [2] 2e e4 [2] 60 e8 [2] 6c e2 [2] 7b e9 [2] 60 a7 [2] 5d }

  condition:
    any of them
}