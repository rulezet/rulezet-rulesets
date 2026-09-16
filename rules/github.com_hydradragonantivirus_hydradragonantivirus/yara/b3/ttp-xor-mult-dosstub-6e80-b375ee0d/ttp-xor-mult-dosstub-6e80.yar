rule TTP_XOR_MULT_DOSStub_6e80 {
  strings:
    $key_6e80 = { 3a e8 [2] 4e f0 [2] 09 f2 [2] 4e e3 [2] 00 ef [2] 0c e5 [2] 1b ee [2] 00 a0 [2] 3d }

  condition:
    any of them
}