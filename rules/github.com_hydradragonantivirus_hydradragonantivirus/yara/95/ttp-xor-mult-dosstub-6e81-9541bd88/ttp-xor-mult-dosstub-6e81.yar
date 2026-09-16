rule TTP_XOR_MULT_DOSStub_6e81 {
  strings:
    $key_6e81 = { 3a e9 [2] 4e f1 [2] 09 f3 [2] 4e e2 [2] 00 ee [2] 0c e4 [2] 1b ef [2] 00 a1 [2] 3d }

  condition:
    any of them
}