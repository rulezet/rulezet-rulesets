rule TTP_XOR_MULT_DOSStub_7e87 {
  strings:
    $key_7e87 = { 2a ef [2] 5e f7 [2] 19 f5 [2] 5e e4 [2] 10 e8 [2] 1c e2 [2] 0b e9 [2] 10 a7 [2] 2d }

  condition:
    any of them
}