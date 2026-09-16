rule TTP_XOR_MULT_DOSStub_7e80 {
  strings:
    $key_7e80 = { 2a e8 [2] 5e f0 [2] 19 f2 [2] 5e e3 [2] 10 ef [2] 1c e5 [2] 0b ee [2] 10 a0 [2] 2d }

  condition:
    any of them
}