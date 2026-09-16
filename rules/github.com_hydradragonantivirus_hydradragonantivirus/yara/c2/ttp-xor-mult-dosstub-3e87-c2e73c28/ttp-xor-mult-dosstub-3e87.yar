rule TTP_XOR_MULT_DOSStub_3e87 {
  strings:
    $key_3e87 = { 6a ef [2] 1e f7 [2] 59 f5 [2] 1e e4 [2] 50 e8 [2] 5c e2 [2] 4b e9 [2] 50 a7 [2] 6d }

  condition:
    any of them
}