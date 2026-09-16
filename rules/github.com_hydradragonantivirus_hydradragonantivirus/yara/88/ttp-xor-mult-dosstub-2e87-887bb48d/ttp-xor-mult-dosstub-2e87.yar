rule TTP_XOR_MULT_DOSStub_2e87 {
  strings:
    $key_2e87 = { 7a ef [2] 0e f7 [2] 49 f5 [2] 0e e4 [2] 40 e8 [2] 4c e2 [2] 5b e9 [2] 40 a7 [2] 7d }

  condition:
    any of them
}