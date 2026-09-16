rule TTP_XOR_MULT_DOSStub_7e81 {
  strings:
    $key_7e81 = { 2a e9 [2] 5e f1 [2] 19 f3 [2] 5e e2 [2] 10 ee [2] 1c e4 [2] 0b ef [2] 10 a1 [2] 2d }

  condition:
    any of them
}